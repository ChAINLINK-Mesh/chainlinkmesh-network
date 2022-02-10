#pragma once
#include <Poco/Net/IPAddress.h>
#include <string>

struct Node {
	static const constexpr std::uint32_t WG_PUBKEY_SIZE = 32;
	using WireGuardPublicKey = std::array<std::uint8_t, WG_PUBKEY_SIZE>;

	std::uint64_t id;
	std::string controlPlanePublicKey;
	WireGuardPublicKey wireGuardPublicKey;
	Poco::Net::IPAddress controlPlaneIP, wireGuardIP;
	std::uint16_t controlPlanePort, wireGuardPort;

	const static std::uint16_t DEFAULT_WIREGUARD_PORT = 274;
};
