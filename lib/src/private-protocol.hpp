#pragma once

#include "peers.hpp"
#include "private-protocol_generated.h"

#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/TCPServer.h>
#include <Poco/Net/TCPServerConnection.h>
#include <Poco/Net/TCPServerConnectionFactory.h>
#include <Poco/Net/TCPServerParams.h>
#include <cstdint>
#include <optional>
#include <span>

namespace PrivateProtocol {
	const constexpr std::uint16_t DEFAULT_CONTROL_PLANE_PORT = 273;
	const constexpr std::uint32_t MAX_PACKET_SIZE = 32 * 1024;

	class PrivateConnection;

	class PrivateProtocolManager {
	public:
		struct Configuration {
			/**
			 * @controlPlanePort What port to run the private protocol on.
			 */
			std::uint16_t controlPlanePort;

			/**
			 * @selfNode The node operating this private protocol.
			 */
			SelfNode selfNode;

			/**
			 * @peers A shared pointer to the list of peers. Not permitted to be
			 * nullptr.
			 */
			std::shared_ptr<Peers> peers;
		};

		/**
		 * @brief Creates a new Private-Protocol Manager from the given
		 * configuration.
		 *
		 * @param config The initial configuration to start with.
		 */
		PrivateProtocolManager(Configuration config);

		/**
		 * @brief Creates a copy of a Private-Protocol Manager. Will create a
		 * duplicate of the other Private-Protocol Manager's peer list, i.e.
		 * subsequent changes will not affect both managers.
		 *
		 * @param other The other Private-Protocol Manager.
		 */
		PrivateProtocolManager(const PrivateProtocolManager& other) = default;
		virtual ~PrivateProtocolManager() = default;

		/**
		 * @brief Decodes a given sequence of bytes into the appropriate packet.
		 *
		 * @param bytes Sequence of bytes to decode.
		 */
		static std::optional<MessageT>
		decode_packet(const std::span<const std::uint8_t>& bytes);

		std::unique_ptr<Poco::Net::TCPServer>
		start(const Poco::Net::ServerSocket& serverSocket,
		      Poco::Net::TCPServerParams::Ptr params);

		/**
		 * @brief Accepts a peer request. Will notify other peers via the
		 *        private protocol.
		 *
		 *        Will not updated existing nodes.
		 *
		 *        Expects peer node to be valid.
		 *
		 * @param originator Which node sent this message. If a node is advertising
		 * itself, then the originator is its own ID.
		 * @param node The node to add to the peer list.
		 */
		virtual void accept_peer_request(std::uint64_t originator,
		                                 const Node& node);

		/**
		 * @brief Gets a list of peers from another node.
		 *
		 *        Will error:
		 *
		 *        * if any node IDs are duplicated
		 *        * if any node is missing a parent
		 *
		 *        Doesn't guarantee that all node details are kept, for instance in
		 *        the case a peer has been deleted from our parent.
		 *
		 * @param self The client's own node details.
		 * @param other The node to request details from.
		 * @param knownNodes The other known nodes. These details don't need to be
		 *                   fetched again.
		 * @return Either the list of peer nodes, or the error which occurred.
		 */
		static Expected<std::vector<Node>>
		get_peers(const SelfNode& self, const Node& other,
		          const std::vector<Node>& knownNodes);

		/**
		 * @brief Converts a node to a peer inform.
		 *
		 * @param peer The peer node.
		 * @return The peer inform command.
		 */
		static PeerInformCommandT convert_node_to_peer_inform(const Node& peer);

		/**
		 * @brief Converts a peer-inform command to a node.
		 *
		 * @param command The peer-inform.
		 * @return The node, or the error which occurred.
		 */
		static Expected<Node>
		convert_peer_inform_to_node(const PeerInformCommandT& command);

		/**
		 * @brief Converts a command union to a message, by signing it.
		 *
		 * @param self The signing node.
		 * @param command The command union to convert.
		 * @return The resulting message.
		 */
		static std::optional<MessageT>
		command_to_message(const SelfNode& self, const CommandUnion& command);

	protected:
		std::uint16_t controlPlanePort;
		std::shared_ptr<Peers> peers;
		SelfNode selfNode;

		/**
		 * @brief Informs an existing peer node about a new peer.
		 *
		 *        Requires the existing peer node's connection details to be known.
		 *
		 * @param node The existing peer's details.
		 * @param newPeer The new peer's details.
		 */
		void inform_node_about_new_peer(const Node& node, const Node& newPeer);

		class ConnectionFactory : public Poco::Net::TCPServerConnectionFactory {
		public:
			ConnectionFactory(PrivateProtocolManager& parent);
			~ConnectionFactory() override = default;

			Poco::Net::TCPServerConnection*
			createConnection(const Poco::Net::StreamSocket& socket) override;

		protected:
			PrivateProtocolManager& parent;
		};

		friend PrivateConnection;
	};

	class PrivateConnection : public Poco::Net::TCPServerConnection {
	public:
		PrivateConnection(const Poco::Net::StreamSocket& socket,
		                  PrivateProtocolManager& parent);
		~PrivateConnection() override = default;

		void run() override;

	protected:
		PrivateProtocolManager& parent;

		void send_error(const std::string& errorMsg);

		// Specific handling functions.
		void handle_peer_inform(const PrivateProtocol::MessageT& message);
		void handle_peer_list();
		void handle_peer_request(const PrivateProtocol::MessageT& message);
	};

	class PrivateProtocolClient {
	public:
		/**
		 * @brief Creates a client which handles a connection to a peer.
		 *
		 *        Requires the peer's connection details to be known.
		 *
		 * @param peer The peer to connect to.
		 */
		PrivateProtocolClient(Node peer);

		/**
		 * @brief Creates a client which re-uses an existing connection to a peer.
		 *
		 * @param socket The existing connection to reuse. Must persist for the
		 *               lifetime of the client.
		 */
		PrivateProtocolClient(Poco::Net::StreamSocket& socket);

		/**
		 * @brief Informs the connected node about a new peer.
		 *
		 * @param self The client's own node details.
		 * @param newPeer The new peer to inform the connected node about.
		 * @return The response message, or the error which occurred.
		 */
		Expected<MessageT> inform_about_new_peer(const SelfNode& self,
		                                         const Node& newPeer);

		/**
		 * @brief Requests the connected node to transmit all peer IDs they have.
		 *
		 * @param self The client's own node details.
		 * @return The response message, or the error which occurred.
		 */
		Expected<MessageT> request_peer_list(const SelfNode& self);

		/**
		 * @brief Requests peer details from the connected node.
		 *
		 * @param self The client's own node details.
		 * @param peerID The ID of the peer to request.
		 * @return The response message, or the error which occurred.
		 */
		Expected<MessageT> request_peer(const SelfNode& self, std::uint64_t peerID);

		/**
		 * @brief Sends a message table to the peer, and receives response.
		 *
		 * @param self The client's own node details.
		 * @param message The Flatbuffer message to send.
		 * @return The response message, or the error which occurred.
		 */
		Expected<MessageT> send_message(const MessageT& message);

		/**
		 * @brief Sends a message table to the peer, without waiting for a response.
		 *
		 * @param message The Flatbuffer message to send.
		 * @return The error which occurred, if any.
		 */
		Expected<void> send_message_nowait(const MessageT& message);

		/**
		 * @brief Sends a message (using a pre-established connection) to a peer,
		 *        waiting for a response.
		 *
		 * @param socket The existing connection's socket.
		 * @param message The Flatbuffer message to send.
		 * @return The response message, or the error which occurred.
		 */
		static Expected<MessageT> send_message(Poco::Net::StreamSocket& socket,
		                                       const MessageT& message);

		/**
		 * @brief Sends a message (using a pre-established connection) to a peer,
		 *        without waiting for a response.
		 *
		 * @param socket The existing connection's socket.
		 * @param message The Flatbuffer message to send.
		 * @return The response message, or the error which occurred.
		 */
		static Expected<void> send_message_nowait(Poco::Net::StreamSocket& socket,
		                                          const MessageT& message);

	protected:
		OptionallyOwned<Poco::Net::StreamSocket> socket;
	};

	// Utility functions for working with the Flatbuffers library
	template <typename T>
	flatbuffers::Optional<T> to_flatbuffers(const std::optional<T>& val) {
		flatbuffers::Optional<T> fb{ flatbuffers::nullopt };

		if (val.has_value()) {
			fb = val.value();
		}

		return fb;
	}
} // namespace PrivateProtocol
