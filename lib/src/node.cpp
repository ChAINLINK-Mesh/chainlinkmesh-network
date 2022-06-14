#include "node.hpp"

#include <Poco/ByteOrder.h>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>

const std::array<std::uint8_t, 8> Node::CHAINLINK_NET_PREFIX{ 0xfd, 0x63, 0x68,
	                                                            0x61, 0x69, 0x6e,
	                                                            0x6c, 0x6b };

Node::IDRangeGenerator Node::generate_id_range() {
	return Node::IDRangeGenerator{ std::numeric_limits<std::uint64_t>::min(),
		                             std::numeric_limits<std::uint64_t>::max() };
}

std::uint64_t Node::generate_id(std::default_random_engine engine) {
	auto idRange = Node::generate_id_range();
	return idRange(engine);
}

Poco::Net::IPAddress Node::get_control_plane_ip(const std::uint64_t nodeID) {
	const auto beNodeID = Poco::ByteOrder::toBigEndian(nodeID);
	const auto* const idBytes = reinterpret_cast<const std::uint8_t*>(&beNodeID);
	in6_addr addr{};
	std::memcpy(addr.s6_addr, Node::CHAINLINK_NET_PREFIX.data(),
	            Node::CHAINLINK_NET_PREFIX.size());
	std::memcpy(addr.s6_addr + Node::CHAINLINK_NET_PREFIX.size(), idBytes,
	            sizeof(beNodeID));

	// Poco::Net::IPAddress performs memcpy on passed pointer, so no issue using
	// address of local variable.
	return Poco::Net::IPAddress{ &addr, sizeof(addr) };
}

bool Node::is_valid() const {
	return controlPlanePublicKey != nullptr && controlPlaneCertificate != nullptr;
}
