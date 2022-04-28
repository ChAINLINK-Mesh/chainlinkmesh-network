#pragma once

#include <array>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <limits>

#include "utilities.hpp"

struct TestPorts {
	Poco::Net::SocketAddress wireGuardAddress;
	Poco::Net::SocketAddress publicProtoAddress;
	Poco::Net::SocketAddress privateProtoAddress;
};

ByteString read_file(const std::string& filename);

template <size_t ReadSize>
std::array<std::uint8_t, ReadSize> read_file(const std::string& filename) {
	const auto fileData = read_file(filename);
	assert(fileData.size() == ReadSize);
	std::array<std::uint8_t, ReadSize> result{};
	std::copy(fileData.begin(), fileData.end(), result.begin());
	return result;
}

/**
 * @brief Gets a randomised configuration of ports to use for testing. Repeated
 *        calls will not overlap until all non-privileged ports have been
 *        exhausted.
 *
 * @return A collection of ports.
 */
TestPorts get_test_ports();

/* Define this method in each testcase. */
void test();
