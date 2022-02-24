#include "server.hpp"
#include "clock.hpp"
#include "types.hpp"
#include <Poco/Net/SocketAddress.h>
#include <Poco/Net/TCPServer.h>
#include <private-protocol.hpp>
#include <public-protocol.hpp>

using PublicProtocol::PublicProtocolManager;

// Assign default socket addresses if custom addresses are not specified.
Server::Server(const Server::Configuration& config)
    : publicProtoAddress{ config.publicProtoAddress.value_or(
	        default_public_proto_address(config.wireGuardAddress)) },
      privateProtoAddress{ config.privateProtoAddress.value_or(
	        default_private_proto_address(config.wireGuardAddress)) },
      wireGuardAddress{ config.wireGuardAddress }, self{ Server::get_self(
	                                                     config) },
      publicProtoManager{ PublicProtocolManager::Configuration{
	        // TODO: replace with a cryptographically secure PSK-generation
	        // function
	        .psk = config.psk.value_or(PublicProtocolManager::DEFAULT_PSK),
	        .self = self,
	        .controlPlanePrivateKey = config.controlPlanePrivateKey,
	        .pskTTL =
	            config.pskTTL.value_or(PublicProtocolManager::DEFAULT_PSK_TTL),
	        .clock = config.clock.value_or(std::make_shared<SystemClock>()),
	    } },
      controlPlanePrivateKey{ config.controlPlanePrivateKey } {}

void Server::ServerExecution::stop() const {
	if (this->publicProtoServer) {
		this->publicProtoServer->stop();
	}

	if (this->privateProtoServer) {
		this->privateProtoServer->stop();
	}
}

Server::ServerExecution Server::start() {
	return ServerExecution{
		.publicProtoServer = this->publicProtoManager.start(
		    Poco::Net::ServerSocket{ this->publicProtoAddress },
		    Server::public_tcp_server_params()),
		.privateProtoServer = {},
	};
}

Poco::Net::SocketAddress Server::get_public_proto_address() {
	return this->publicProtoAddress;
}

Poco::Net::SocketAddress Server::get_private_proto_address() {
	return this->privateProtoAddress;
}

Poco::Net::SocketAddress Server::get_wireguard_address() {
	return this->wireGuardAddress;
}

Poco::Net::TCPServerParams::Ptr Server::public_tcp_server_params() {
	auto* params = new Poco::Net::TCPServerParams{};
	params->setMaxThreads(1);
	params->setMaxQueued(4);

	return params;
}

Node Server::get_self(const Server::Configuration& config) {
	const auto privateProtoAddress = config.privateProtoAddress.value_or(
	    default_private_proto_address(config.wireGuardAddress));

	// TODO: replace with actual implementation
	return Node{
		.id = 987654321,
		.controlPlanePublicKey = config.controlPlanePrivateKey,
		.wireGuardPublicKey = config.meshPublicKey,
		.controlPlaneIP = privateProtoAddress.host(),
		.wireGuardIP = config.wireGuardAddress.host(),
		.controlPlanePort = privateProtoAddress.port(),
		.wireGuardPort = config.wireGuardAddress.port(),
		.controlPlaneCertificate = config.controlPlaneCertificate,
	};
}

std::string Server::get_psk() const {
	return publicProtoManager.get_psk();
}

std::optional<std::tuple<std::uint64_t, SHA256_Hash, SHA256_Signature>>
Server::get_signed_psk() const {
	return publicProtoManager.get_signed_psk();
}

Node Server::get_self() const {
	return self;
}

Poco::Net::SocketAddress Server::default_public_proto_address(
    const Poco::Net::SocketAddress& wireguard) {
	return Poco::Net::SocketAddress{ wireguard.host(),
		                               PublicProtocol::DEFAULT_CONTROL_PLANE_PORT };
}

Poco::Net::SocketAddress Server::default_private_proto_address(
    const Poco::Net::SocketAddress& wireguard) {
	return Poco::Net::SocketAddress{
		wireguard.host(), PrivateProtocol::DEFAULT_CONTROL_PLANE_PORT
	};
}
