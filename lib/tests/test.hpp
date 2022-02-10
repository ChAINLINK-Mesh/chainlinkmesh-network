#pragma once

#include <array>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <limits>

/* Define this method in each testcase. */
void test();

std::string read_file(const std::string& filename);

template <size_t ReadSize>
std::array<std::uint8_t, ReadSize> read_file(const std::string& filename) {
	const auto fileData = read_file(filename);
	assert(fileData.size() == ReadSize);
	std::array<std::uint8_t, ReadSize> result{};
	std::copy(fileData.begin(), fileData.end(), result.begin());
	return result;
}
