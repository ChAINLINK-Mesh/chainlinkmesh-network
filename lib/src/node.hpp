#pragma once
#include "types.hpp"
#include "wireguard.hpp"
#include <Poco/Net/IPAddress.h>
#include <random>

struct Node {
	std::uint64_t id;
	EVP_PKEY_RAII controlPlanePublicKey;
	AbstractWireGuardManager::Key wireGuardPublicKey;
	Poco::Net::IPAddress controlPlaneIP, wireGuardIP;
	std::uint16_t controlPlanePort, wireGuardPort;
	X509_RAII controlPlaneCertificate = nullptr;

	const static std::uint16_t DEFAULT_WIREGUARD_PORT = 274;
	const static std::array<std::uint8_t, 8> CHAINLINK_NET_PREFIX;
	const constexpr static std::uint8_t CHAINLINK_NET_PREFIX_BITS =
	    CHAINLINK_NET_PREFIX.size() * 8;

	using IDRangeGenerator = std::uniform_int_distribution<std::uint64_t>;
	static IDRangeGenerator generate_id_range();
};
