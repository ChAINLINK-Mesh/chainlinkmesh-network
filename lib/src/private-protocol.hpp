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
		 * @brief Sends a message table to the peer, and receives response.
		 *
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
