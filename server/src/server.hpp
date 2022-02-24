#pragma once

#include "types.hpp"
#include <Poco/Net/SocketAddress.h>
#include <Poco/Net/TCPServer.h>
#include <cstdint>
#include <optional>
#include <public-protocol.hpp>

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
		 * The control-plane private key
		 *
		 * Used to sign messages to other peers.
		 */
		EVP_PKEY_RAII controlPlanePrivateKey;

		/**
		 * The data-plane's public key used to encrypt transmissions.
		 */
		Node::WireGuardPublicKey meshPublicKey;

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
		 * The control-plane IP:port to listen on for private-protocol
		 * communications.
		 *
		 * A value of std::nullopt implies the default address should be used.
		 */
		std::optional<Poco::Net::SocketAddress> privateProtoAddress;

		/**
		 * The control-plane certificate used to sign peer CSRs.
		 */
		X509_RAII controlPlaneCertificate;

		/**
		 * The PSK used to authenticate initialisation requests.
		 */
		std::optional<std::string> psk;

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
	};

	/**
	 * @brief Construct a new Server instance.
	 *
	 * @param config the server configuration to start with
	 * @param controlPlanePrivateKey the private-key to sign certificates with
	 */
	explicit Server(const Configuration& config);

	struct ServerExecution {
		std::unique_ptr<Poco::Net::TCPServer> publicProtoServer;
		std::unique_ptr<Poco::Net::TCPServer> privateProtoServer;

		void stop() const;
	};

	ServerExecution start();

	Poco::Net::SocketAddress get_public_proto_address();
	Poco::Net::SocketAddress get_private_proto_address();
	Poco::Net::SocketAddress get_wireguard_address();

	std::string get_psk() const;
	std::optional<std::tuple<std::uint64_t, SHA256_Hash, SHA256_Signature>>
	get_signed_psk() const;
	Node get_self() const;

protected:
	Poco::Net::SocketAddress publicProtoAddress;
	Poco::Net::SocketAddress privateProtoAddress;
	Poco::Net::SocketAddress wireGuardAddress;
	Node self;
	PublicProtocol::PublicProtocolManager publicProtoManager;
	EVP_PKEY_RAII controlPlanePrivateKey;

	/**
	 * @brief Dynamically allocates TCP server parameters for the public
	 *        control-plane server.
	 *
	 * @return Poco::Net::TCPServerParams::Ptr TCP server parameters
	 */
	static Poco::Net::TCPServerParams::Ptr public_tcp_server_params();

	static Node get_self(const Configuration& config);

	static Poco::Net::SocketAddress default_public_proto_address(
	    const Poco::Net::SocketAddress& wireGuardAddress);
	static Poco::Net::SocketAddress default_private_proto_address(
	    const Poco::Net::SocketAddress& wireGuardAddress);
};
