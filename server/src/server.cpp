#include "server.hpp"
#include "clock.hpp"
#include "linux-wireguard-manager.hpp"
#include "types.hpp"
#include "wireguard.hpp"
#include <Poco/Net/SocketAddress.h>
#include <Poco/Net/TCPServer.h>
#include <functional>
#include <private-protocol.hpp>
#include <public-protocol.hpp>
#include <random>
#include <utility>

using PublicProtocol::PublicProtocolManager;

LinuxPublicProtocolManager::LinuxPublicProtocolManager(
    Configuration config, std::function<bool(const Node& node)> addNodeCallback)
    : PublicProtocolManager{ std::move(config) }, addNodeCallback{ std::move(
	                                                    addNodeCallback) } {}

bool LinuxPublicProtocolManager::add_node(const Node& node) {
	PublicProtocolManager::add_node(node);
	return addNodeCallback(node);
}

// Assign default socket addresses if custom addresses are not specified.
Server::Server(const Server::Configuration& config)
    : randomEngine{ config.randomEngine.value_or(
	        std::default_random_engine{ std::random_device{}() }) },
      self{ this->get_self(config) },
      publicProtoAddress{ config.publicProtoAddress.value_or(
	        default_public_proto_address(config.wireGuardAddress)) },
      privateProtoPort{ self.controlPlanePort },
      wireGuardAddress{ config.wireGuardAddress },
      publicProtoManager{
	      PublicProtocolManager::Configuration{
	          // TODO: replace with a cryptographically secure PSK-generation
	          // function
	          .psk = config.psk.value_or(PublicProtocolManager::DEFAULT_PSK),
	          .self = self,
	          .controlPlanePrivateKey = config.controlPlanePrivateKey,
	          .pskTTL =
	              config.pskTTL.value_or(PublicProtocolManager::DEFAULT_PSK_TTL),
	          .clock = config.clock.value_or(std::make_shared<SystemClock>()),
	          .peers = config.peers,
	          .randomEngine = randomEngine,
	      },
	      [t = this](const Node& node) { return t->add_node(node); }
      },
      wireGuardPrivateKey{ config.meshPrivateKey },
      wireGuardPublicKey{ config.meshPublicKey },
      controlPlanePrivateKey{ config.controlPlanePrivateKey }, idRange{
	      Node::generate_id_range()
      } {}

void Server::start() {
	// Semantics unclear for repeated starts.
	assert(!execution.has_value());

	// TODO: Prefill the interface with a list of saved other nodes.
	LinuxWireGuardManager wgManager{ this->self,
		                               this->publicProtoManager.get_peer_nodes(),
		                               this->wireGuardPrivateKey, randomEngine };
	wgManager.setup_interface();
	execution.emplace(ServerExecution{
	    .publicProtoServer = this->publicProtoManager.start(
	        Poco::Net::ServerSocket{ this->publicProtoAddress },
	        Server::public_tcp_server_params()),
	    .privateProtoServer = {},
	    .wgManager = std::move(wgManager),
	});
}

void Server::stop() {
	// If we weren't executing, opportunistically return.
	if (!execution) {
		return;
	}

	if (execution->publicProtoServer) {
		execution->publicProtoServer->stop();
	}

	if (execution->privateProtoServer) {
		execution->privateProtoServer->stop();
	}

	execution->wgManager.teardown_interface();
}

Poco::Net::SocketAddress Server::get_public_proto_address() const {
	return this->publicProtoAddress;
}

Poco::Net::SocketAddress Server::get_private_proto_address() const {
	return Poco::Net::SocketAddress{ this->self.controlPlaneIP,
		                               this->self.controlPlanePort };
}

Poco::Net::SocketAddress Server::get_wireguard_address() const {
	return this->wireGuardAddress;
}

Poco::Net::TCPServerParams::Ptr Server::public_tcp_server_params() {
	auto* params = new Poco::Net::TCPServerParams{};
	params->setMaxThreads(1);
	params->setMaxQueued(4);

	return params;
}

Node Server::get_self(const Server::Configuration& config) {
	const auto id = config.id.value_or(idRange(randomEngine));

	// The host for the private protocol is deterministically mapped according to
	// the node ID, so enforce this relationship.
	const auto privateProtoHost =
	    AbstractWireGuardManager::get_internal_ip_address(id);
	const auto privateProtoPort = config.privateProtoPort.value_or(
	    PrivateProtocol::DEFAULT_CONTROL_PLANE_PORT);

	return Node{
		.id = id,
		.controlPlanePublicKey = config.controlPlanePrivateKey,
		.wireGuardPublicKey = config.meshPublicKey,
		.controlPlaneIP = privateProtoHost,
		.wireGuardIP = config.wireGuardAddress.host(),
		.controlPlanePort = privateProtoPort,
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

bool Server::add_node(const Node& node) {
	assert(execution.has_value());

	execution->wgManager.add_peer(AbstractWireGuardManager::Peer{
	    .publicKey = node.wireGuardPublicKey,
			// We cannot be sure about where nodes will connect from if we are the server.
	    .endpoint = std::nullopt,
	        //Poco::Net::SocketAddress{ node.wireGuardIP, node.wireGuardPort },
	    .internalAddress =
	        AbstractWireGuardManager::get_internal_ip_address(node.id),
	});

	return true;
}
