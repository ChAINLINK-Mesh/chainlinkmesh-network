#include "private-protocol.hpp"

#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/TCPServerConnection.h>

namespace PrivateProtocol {
	PrivateProtocolManager::PrivateProtocolManager(const Configuration& config)
	    : controlPlanePort{ config.controlPlanePort }, peers{ config.peers } {
		// Prevent nullptr being passed.
		assert(config.peers);
	}

	std::optional<MessageT>
	PrivateProtocolManager::decode_packet(const std::span<std::uint8_t>& bytes) {
		flatbuffers::Verifier verifier{ bytes.data(), bytes.size() };
		if (!VerifyMessageBuffer(verifier)) {
			return std::nullopt;
		}

		MessageT message{};
		GetMessage(bytes.data())->UnPackTo(&message);

		return message;
	}

	std::unique_ptr<Poco::Net::TCPServer>
	PrivateProtocolManager::start(const Poco::Net::ServerSocket& serverSocket,
	                              Poco::Net::TCPServerParams::Ptr params) {
		auto server = std::make_unique<Poco::Net::TCPServer>(
		    new ConnectionFactory(*this), serverSocket, std::move(params));
		server->start();

		return server;
	}

	PrivateProtocolManager::ConnectionFactory::ConnectionFactory(
	    PrivateProtocolManager& parent)
	    : parent{ parent } {}

	Poco::Net::TCPServerConnection*
	PrivateProtocolManager::ConnectionFactory::createConnection(
	    const Poco::Net::StreamSocket& socket) {
		return new PrivateConnection{ socket, parent };
	}

	PrivateConnection::PrivateConnection(const Poco::Net::StreamSocket& socket,
	                                     PrivateProtocolManager& parent)
	    : Poco::Net::TCPServerConnection{ socket }, parent{ parent } {}

	void PrivateConnection::run() {
		throw "TODO: Unimplemented";
	}
} // namespace PrivateProtocol
