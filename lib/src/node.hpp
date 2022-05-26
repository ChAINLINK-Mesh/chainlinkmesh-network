#pragma once

#include "types.hpp"
#include "wireguard.hpp"

#include <Poco/Net/IPAddress.h>
#include <random>

struct NodeConnection {
	std::uint16_t controlPlanePort;
	Host wireGuardHost;
	std::uint16_t wireGuardPort;
};

struct Node {
	std::uint64_t id;
	EVP_PKEY_RAII controlPlanePublicKey;
	AbstractWireGuardManager::Key wireGuardPublicKey;
	Poco::Net::IPAddress controlPlaneIP;
	std::optional<NodeConnection> connectionDetails;
	X509_RAII controlPlaneCertificate;
	std::optional<std::uint64_t> parent;

	const constexpr static std::uint16_t DEFAULT_WIREGUARD_PORT = 274;
	const static std::array<std::uint8_t, 8> CHAINLINK_NET_PREFIX;
	const constexpr static std::uint8_t CHAINLINK_NET_PREFIX_BITS =
	    CHAINLINK_NET_PREFIX.size() * 8;

	using IDRangeGenerator = std::uniform_int_distribution<std::uint64_t>;
	[[nodiscard]] static IDRangeGenerator generate_id_range();

	[[nodiscard]] static std::uint64_t
	generate_id(std::default_random_engine engine = {});

	/**
	 * @brief Converts an ID into a corresponding control-plane IP address using a
	 *        1-1 mapping.
	 *
	 * @param nodeID The ID of the node to get an IP for.
	 * @return The control-plane address of the node being looked up.
	 */
	[[nodiscard]] static Poco::Net::IPAddress
	get_control_plane_ip(std::uint64_t nodeID);
};

struct SelfNode : public Node {
	EVP_PKEY_RAII controlPlanePrivateKey;
	AbstractWireGuardManager::Key wireGuardPrivateKey;
	std::optional<ByteString> psk;
	std::optional<std::uint64_t> pskTTL;
};
