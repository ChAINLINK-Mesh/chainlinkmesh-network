#pragma once

#include "linux-wireguard-manager.hpp"
#include "node.hpp"
#include "public-protocol.hpp"
#include "types.hpp"
#include "wireguard.hpp"

#include <Poco/AutoPtr.h>
#include <Poco/Net/SocketAddress.h>
#include <Poco/Net/TCPServer.h>
#include <Poco/Util/MapConfiguration.h>
#include <Poco/Util/PropertyFileConfiguration.h>
#include <cstdint>
#include <optional>
#include <random>

// Specialisation, which can specifically handle peers joining the Linux WG
// interface.
class LinuxPeers : public Peers {
public:
	LinuxPeers(LinuxWireGuardManager& wireguardManager);
	LinuxPeers(const std::vector<Node>& nodes,
	           LinuxWireGuardManager& wireguardManager);
	/**
	 * @brief Copy constructor is deleted, as the wireguardManager reference
	 * member would be shared, and the mutex would not be, hence accesses would
	 * not be synchronised.
	 */
	LinuxPeers(const LinuxPeers& other) = delete;
	LinuxPeers(LinuxPeers&& other) noexcept;

	bool add_peer(Node node) override;
	void update_peer(Node node) override;
	std::optional<Node> delete_peer(std::uint64_t nodeID) override;

protected:
	std::mutex wireguardManagerMutex;
	LinuxWireGuardManager& wireguardManager;
};

class Server {
public:
	/**
	 * A structure representing the server configuration.
	 */
	struct Configuration {
		/**
		 * The server node's ID.
		 *
		 * A value of std::nullopt indicates that it should be randomly assigned.
		 * This is only valid for the root node. Other nodes will have their ID
		 * values assigned automatically
		 */
		std::optional<std::uint64_t> id;

		/**
		 * @parent The parent node's ID.
		 *
		 * A value of std::nullopt indicates that this node does not have a parent,
		 * i.e. it is the root node.
		 */
		std::optional<std::uint64_t> parent;

		/**
		 * The control-plane private key
		 *
		 * Used to sign messages to other peers.
		 */
		EVP_PKEY_RAII controlPlanePrivateKey;

		/**
		 * The data-plane's public key used to encrypt transmissions.
		 */
		AbstractWireGuardManager::Key meshPublicKey;

		/**
		 * The data-plane's private key used to encrypt transmissions.
		 */
		AbstractWireGuardManager::Key meshPrivateKey;

		/**
		 * The data-plane's IP:port pair to listen on for data transmission.
		 */
		Poco::Net::SocketAddress wireGuardAddress;

		/**
		 * The control-plane IP:port to listen on for public-protocol
		 * communications.
		 *
		 * A value of std::nullopt implies the default address should be used.
		 */
		std::optional<Poco::Net::SocketAddress> publicProtoAddress;

		/**
		 * The control-plane port to listen on for private-protocol
		 * communications. Uses the internal WG IP, which is deterministic.
		 *
		 * A value of std::nullopt implies the default port should be used.
		 */
		std::optional<std::uint16_t> privateProtoPort;

		/**
		 * The control-plane certificate used to sign peer CSRs.
		 */
		X509_RAII controlPlaneCertificate;

		/**
		 * The PSK used to authenticate initialisation requests.
		 */
		std::optional<ByteString> psk;

		/**
		 * The TTL for request PSK values.
		 *
		 * A value of std::nullopt implies the default TTL should be used.
		 */
		std::optional<std::uint64_t> pskTTL;

		/**
		 * The clock used to check the current time.
		 *
		 * A value of std::nullopt implies the default TTL should be used.
		 */
		std::optional<Clock> clock;

		/**
		 * The list of peer nodes which should be have connections established to.
		 *
		 * An empty list is useful if this node is the root CA, and hence has no
		 * peers yet.
		 */
		std::vector<Node> peers;

		/**
		 * The source of random value generation. Allows encapsulating randomness
		 * within tests.
		 *
		 * A value of std::nullopt implies that a randomly seeded generator shall be
		 * used.
		 */
		std::optional<std::default_random_engine> randomEngine;
	};

	/**
	 * @brief Construct a new Server instance.
	 *
	 * @param config the server configuration to start with
	 * @param controlPlanePrivateKey the private-key to sign certificates with
	 */
	explicit Server(const Configuration& config);

	void start();
	void stop();

	Poco::Net::SocketAddress get_public_proto_address() const;
	Poco::Net::SocketAddress get_private_proto_address() const;
	Poco::Net::SocketAddress get_wireguard_address() const;

	ByteString get_psk() const;
	std::optional<std::tuple<std::uint64_t, SHA256_Hash, SHA256_Signature>>
	get_signed_psk() const;
	SelfNode get_self() const;

	std::vector<Node> get_peer_nodes() const;

	Poco::AutoPtr<Poco::Util::PropertyFileConfiguration>
	get_configuration() const;

	static Expected<Configuration> get_configuration_from_saved_config(
	    const Poco::AutoPtr<Poco::Util::PropertyFileConfiguration>& properties);

protected:
	Node::IDRangeGenerator idRange;
	std::default_random_engine randomEngine;
	SelfNode self;
	LinuxWireGuardManager wgManager;
	std::shared_ptr<LinuxPeers> peers;
	Poco::Net::SocketAddress publicProtoAddress;
	std::uint16_t privateProtoPort;
	Poco::Net::SocketAddress wireGuardAddress;
	PublicProtocol::PublicProtocolManager publicProtoManager;

	struct ServerExecution {
		std::unique_ptr<Poco::Net::TCPServer> publicProtoServer;
		std::unique_ptr<Poco::Net::TCPServer> privateProtoServer;
	};

	std::optional<ServerExecution> execution;

	/**
	 * @brief Dynamically allocates TCP server parameters for the public
	 *        control-plane server.
	 *
	 * @return Poco::Net::TCPServerParams::Ptr TCP server parameters
	 */
	static Poco::Net::TCPServerParams::Ptr public_tcp_server_params();

	SelfNode get_self(const Configuration& config);

	static Poco::AutoPtr<Poco::Util::MapConfiguration>
	get_node_configuration(const Node& node);

	static Poco::Net::SocketAddress default_public_proto_address(
	    const Poco::Net::SocketAddress& wireGuardAddress);

	bool add_node(const Node& node);
};
