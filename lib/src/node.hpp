#pragma once
#include <Poco/Net/IPAddress.h>
#include <string>

struct Node {
	using WireGuardPublicKey = std::string;

	std::uint64_t id;
	WireGuardPublicKey publicKey;
	Poco::Net::IPAddress meshIP, wireguardIP;
	std::uint16_t controlPlanePort, wireguardPort;

	const static std::uint16_t DEFAULT_CONTROL_PLANE_PORT = 272;
	const static std::uint16_t DEFAULT_WIREGUARD_PORT = 273;
};
