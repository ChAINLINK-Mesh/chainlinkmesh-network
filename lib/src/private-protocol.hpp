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

	class PrivateProtocolManager {
	public:
		struct Configuration {
			/**
			 * @controlPlanePort What port to run the private protocol on.
			 */
			std::uint16_t controlPlanePort;

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
		PrivateProtocolManager(const Configuration& config);

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
		decode_packet(const std::span<std::uint8_t>& bytes);

		std::unique_ptr<Poco::Net::TCPServer>
		start(const Poco::Net::ServerSocket& serverSocket,
		      Poco::Net::TCPServerParams::Ptr params);

	protected:
		std::uint16_t controlPlanePort;
		std::shared_ptr<Peers> peers;

		class ConnectionFactory : public Poco::Net::TCPServerConnectionFactory {
		public:
			ConnectionFactory(PrivateProtocolManager& parent);
			~ConnectionFactory() override = default;

			Poco::Net::TCPServerConnection*
			createConnection(const Poco::Net::StreamSocket& socket) override;

		protected:
			PrivateProtocolManager& parent;
		};
	};

	class PrivateConnection : public Poco::Net::TCPServerConnection {
	public:
		PrivateConnection(const Poco::Net::StreamSocket& socket,
		                  PrivateProtocolManager& parent);
		~PrivateConnection() override = default;

		void run() override;

	protected:
		PrivateProtocolManager& parent;
	};
} // namespace PrivateProtocol
