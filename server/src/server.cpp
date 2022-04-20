#include "server.hpp"
#include "certificates.hpp"
#include "clock.hpp"
#include "linux-wireguard-manager.hpp"
#include "private-protocol.hpp"
#include "public-protocol.hpp"
#include "types.hpp"
#include "wireguard.hpp"

#include <Poco/Exception.h>
#include <Poco/Net/SocketAddress.h>
#include <Poco/Net/TCPServer.h>
#include <Poco/Util/IniFileConfiguration.h>
#include <exception>
#include <functional>
#include <limits>
#include <random>
#include <stdexcept>
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
      idRange{ Node::generate_id_range() } {}

void Server::start() {
	// Semantics unclear for repeated starts.
	assert(!execution.has_value());

	// TODO: Prefill the interface with a list of saved other nodes.
	LinuxWireGuardManager wgManager{ this->self,
		                               this->publicProtoManager.get_peer_nodes(),
		                               this->self.wireGuardPrivateKey,
		                               randomEngine };
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

SelfNode Server::get_self(const Server::Configuration& config) {
	const auto id = config.id.value_or(idRange(randomEngine));

	// The host for the private protocol is deterministically mapped according to
	// the node ID, so enforce this relationship.
	const auto privateProtoHost =
	    AbstractWireGuardManager::get_internal_ip_address(id);
	const auto privateProtoPort = config.privateProtoPort.value_or(
	    PrivateProtocol::DEFAULT_CONTROL_PLANE_PORT);

	return SelfNode{
		{
		    .id = id,
		    .controlPlanePublicKey = config.controlPlanePrivateKey,
		    .wireGuardPublicKey = config.meshPublicKey,
		    .controlPlaneIP = privateProtoHost,
		    .controlPlanePort = privateProtoPort,
		    .wireGuardHost = Host{ config.wireGuardAddress },
		    .wireGuardPort = config.wireGuardAddress.port(),
		    .controlPlaneCertificate = config.controlPlaneCertificate,
		},
		config.controlPlanePrivateKey,
		config.meshPrivateKey,
		config.psk.value_or(PublicProtocolManager::DEFAULT_PSK),
		config.pskTTL.value_or(PublicProtocolManager::DEFAULT_PSK_TTL),
	};
}

std::vector<Node> Server::get_peer_nodes() const {
	return publicProtoManager.get_peer_nodes();
}

Poco::AutoPtr<Poco::Util::PropertyFileConfiguration>
Server::get_configuration() const {
	Poco::AutoPtr<Poco::Util::PropertyFileConfiguration> configuration{
		new Poco::Util::PropertyFileConfiguration{}
	};

	const auto serverDetails = get_self();
	using CertEncoder = GenericCertificateManager<char>;

	configuration->setUInt64("id", serverDetails.id);
	configuration->setString(
	    "control-plane-private-key",
	    CertEncoder::encode_pem(serverDetails.controlPlanePrivateKey));
	configuration->setString(
	    "mesh-public-key",
	    base64_encode(serverDetails.wireGuardPublicKey).value());
	configuration->setString(
	    "mesh-private-key",
	    base64_encode(serverDetails.wireGuardPrivateKey).value());
	configuration->setString(
	    "certificate",
	    CertEncoder::encode_pem(serverDetails.controlPlaneCertificate));
	configuration->setString("mesh-address", get_wireguard_address().toString());
	configuration->setString("public-proto-address",
	                         get_public_proto_address().toString());
	configuration->setUInt("private-proto-port", privateProtoPort);
	configuration->setString("psk", base64_encode(serverDetails.psk).value());
	configuration->setUInt64("psk-ttl", serverDetails.pskTTL);

	if (serverDetails.parent.has_value()) {
		configuration->setUInt64("parent", serverDetails.parent.value());
	}

	for (const auto& peer : get_peer_nodes()) {
		auto peerConfig = get_node_configuration(peer);
		peerConfig->copyTo(*configuration);
	}

	return configuration;
}

Expected<Server::Configuration> Server::get_configuration_from_saved_config(
    const Poco::AutoPtr<Poco::Util::PropertyFileConfiguration>& properties) {
	using CertEncoder = GenericCertificateManager<char>;
	class DecodingError : public std::runtime_error {
		using std::runtime_error::runtime_error;
	};

	try {
		const auto id = properties->getUInt64("id");
		const auto controlPlanePrivateKey = CertEncoder::decode_pem_private_key(
		    properties->getString("control-plane-private-key"));

		if (!controlPlanePrivateKey) {
			throw DecodingError{
				"Could not decode control-plane private key as PEM"
			};
		}

		const auto meshPublicKey =
		    base64_decode(properties->getString("mesh-public-key"));

		if (!meshPublicKey ||
		    meshPublicKey.value().size() != AbstractWireGuardManager::WG_KEY_SIZE) {
			throw DecodingError{ "Could not decode mesh public key as base64" };
		}

		const auto meshPrivateKey =
		    base64_decode(properties->getString("mesh-private-key"));

		if (!meshPrivateKey || meshPrivateKey.value().size() !=
		                           AbstractWireGuardManager::WG_KEY_SIZE) {
			throw DecodingError{ "Could not decode mesh private key as Base64" };
		}

		const auto wireGuardAddress =
		    Poco::Net::SocketAddress{ properties->getString("mesh-address") };

		const auto publicProtoAddress = Poco::Net::SocketAddress{
			properties->getString("public-proto-address")
		};

		const auto privateProtoPort = properties->getUInt("private-proto-port");

		if (privateProtoPort > std::numeric_limits<std::uint16_t>::max()) {
			throw DecodingError{
				"Could not decode private protocol port (too large)"
			};
		}

		const auto controlPlaneCertificate = CertEncoder::decode_pem_certificate(
		    properties->getString("certificate"));

		if (!controlPlaneCertificate) {
			throw DecodingError{
				"Could not decode control plane certificate as PEM"
			};
		}

		const auto psk = base64_decode(properties->getString("psk"));

		if (!psk) {
			throw DecodingError{ "Could not decode PSK as Base64" };
		}

		const auto pskTTL = properties->getUInt64("psk-ttl");

		std::vector<Node> peers{};

		Poco::Util::IniFileConfiguration::Keys keys{};
		properties->keys("nodes", keys);

		for (const auto& key : keys) {
			const auto peerID = std::stoull(key);
			const auto peerName = "nodes." + key;
			const auto peerControlPlanePublicKey = CertEncoder::decode_pem_public_key(
			    properties->getString(peerName + ".control-plane-public-key"));

			if (!peerControlPlanePublicKey) {
				throw DecodingError{ "Could not decode peer public key as PEM" };
			}

			const auto peerWireGuardPublicKey = base64_decode(
			    properties->getString(peerName + ".wireguard-public-key"));

			if (!peerWireGuardPublicKey ||
			    peerWireGuardPublicKey->size() !=
			        AbstractWireGuardManager::WG_KEY_SIZE) {
				throw DecodingError{ "Could not decode peer WireGuard key as Base64" };
			}

			const auto peerControlPlaneAddress = Poco::Net::SocketAddress{
				properties->getString(peerName + ".control-plane-address")
			};

			const auto peerWireGuardAddress = Poco::Net::SocketAddress{
				properties->getString(peerName + ".wireguard-address")
			};

			const auto peerControlPlaneCertificate = CertEncoder::decode_pem_certificate(
					properties->getString(peerName + ".control-plane-certificate")
					);

			if (!peerControlPlaneCertificate) {
				throw DecodingError{ "Could not decode peer certificate as PEM" };
			}

			std::optional<std::uint64_t> peerParent{};

			if (properties->has(peerName + ".parent")) {
				peerParent = properties->getUInt64(peerName + ".parent");
			}

			Node peer{
				.id = peerID,
				.controlPlanePublicKey = peerControlPlanePublicKey.value(),
				.wireGuardPublicKey = {},
				.controlPlaneIP = peerControlPlaneAddress.host(),
				.controlPlanePort = peerControlPlaneAddress.port(),
				.wireGuardHost = Host{ peerWireGuardAddress.host() },
					.wireGuardPort = peerWireGuardAddress.port(),
				.controlPlaneCertificate = peerControlPlaneCertificate.value(),
				.parent = peerParent,
			};

			std::copy(peerWireGuardPublicKey->begin(), peerWireGuardPublicKey->end(),
			          peer.wireGuardPublicKey.begin());

			peers.emplace_back(std::move(peer));
		}

		Configuration config{
			.id = id,
			.controlPlanePrivateKey = controlPlanePrivateKey.value(),
			.meshPublicKey = {},
			.meshPrivateKey = {},
			.wireGuardAddress = wireGuardAddress,
			.publicProtoAddress = publicProtoAddress,
			.privateProtoPort = privateProtoPort,
			.controlPlaneCertificate = controlPlaneCertificate.value(),
			.psk = psk.value(),
			.pskTTL = pskTTL,
			.peers = peers,
		};

		std::copy(meshPublicKey.value().begin(), meshPublicKey.value().end(),
		          config.meshPublicKey.begin());

		std::copy(meshPrivateKey.value().begin(), meshPrivateKey.value().end(),
		          config.meshPrivateKey.begin());

		return config;
	} catch (const Poco::NotFoundException& e) {
		// If we cannot find a key, return failure.
		return std::make_exception_ptr(e);
	} catch (const Poco::SyntaxException& e) {
		// If we find an invalid property value, return failure.
		return std::make_exception_ptr(e);
	} catch (const DecodingError& e) {
		// If we cannot properly decode a propery value, return failure.
		return std::make_exception_ptr(e);
	} catch (const Poco::InvalidArgumentException& e) {
		// If a property cannot be parsed by Poco, return failure.
		return std::make_exception_ptr(e);
	} catch (const std::invalid_argument& e) {
		// If a number cannot be converted from string by stoull, return failure.
		return std::make_exception_ptr(e);
	}
}

Poco::AutoPtr<Poco::Util::MapConfiguration>
Server::get_node_configuration(const Node& node) {
	const std::string nodeName = "node." + std::to_string(node.id);

	Poco::AutoPtr<Poco::Util::MapConfiguration> configuration{
		new Poco::Util::MapConfiguration{}
	};

	using CertEncoder = GenericCertificateManager<char>;

	configuration->setString(nodeName + ".control-plane-public-key",
	                         CertEncoder::encode_pem(node.controlPlanePublicKey));
	configuration->setString(nodeName + ".wireguard-public-key",
	                         base64_encode(node.wireGuardPublicKey).value());
	configuration->setString(
	    nodeName + ".control-plane-address",
	    Poco::Net::SocketAddress{ node.controlPlaneIP, node.controlPlanePort }
	        .toString());
	// TODO: Encode the raw Host value, to avoid losing DNS lookup functionality.
	configuration->setString(
	    nodeName + ".wireguard-address",
	    Poco::Net::SocketAddress{ node.wireGuardHost, node.wireGuardPort }
	        .toString());
	configuration->setString(
	    nodeName + ".control-plane-certificate",
	    CertEncoder::encode_pem(node.controlPlaneCertificate));

	if (node.parent.has_value()) {
		configuration->setUInt64(nodeName + ".parent", node.parent.value());
	}

	return configuration;
}

ByteString Server::get_psk() const {
	return publicProtoManager.get_psk();
}

std::optional<std::tuple<std::uint64_t, SHA256_Hash, SHA256_Signature>>
Server::get_signed_psk() const {
	return publicProtoManager.get_signed_psk();
}

SelfNode Server::get_self() const {
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
	    // We cannot be sure about where nodes will connect from if we are the
	    // server.
	    .endpoint = std::nullopt,
	    // Poco::Net::SocketAddress{ node.wireGuardIP, node.wireGuardPort },
	    .internalAddress =
	        AbstractWireGuardManager::get_internal_ip_address(node.id),
	});

	return true;
}
