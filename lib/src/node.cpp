#include "node.hpp"

#include <cstdint>
#include <limits>
#include <random>

const std::array<std::uint8_t, 8> Node::CHAINLINK_NET_PREFIX{ 0xfd, 0x63, 0x68,
	                                                            0x61, 0x69, 0x6e,
	                                                            0x6c, 0x6b };

Node::IDRangeGenerator Node::generate_id_range() {
	return Node::IDRangeGenerator{ std::numeric_limits<std::uint64_t>::min(),
		                             std::numeric_limits<std::uint64_t>::max() };
}
