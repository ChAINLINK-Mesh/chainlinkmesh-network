#pragma once
#include <Poco/Net/IPAddress.h>
#include <string>

struct Node {
	static const constexpr std::uint32_t WG_PUBKEY_SIZE = 32;
	using WireGuardPublicKey = std::array<std::uint8_t, WG_PUBKEY_SIZE>;

	std::uint64_t id;
	WireGuardPublicKey controlPlanePublicKey;
	std::string meshPublicKey;
	Poco::Net::IPAddress meshIP, wireguardIP;
	std::uint16_t controlPlanePort, wireguardPort;

	const static std::uint16_t DEFAULT_CONTROL_PLANE_PORT = 272;
	const static std::uint16_t DEFAULT_WIREGUARD_PORT = 273;
};
