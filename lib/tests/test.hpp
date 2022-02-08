#pragma once
#include <cassert>
#include <fstream>

std::string read_file(const std::string& filename) {
	std::ifstream file{ filename };
	const auto fileSize = std::filesystem::file_size(filename);
	assert(fileSize < std::numeric_limits<long>::max());

	std::string fileData(fileSize, '\0');
	file.read(fileData.data(), static_cast<long>(fileSize));
	return fileData;
}

template <size_t ReadSize>
std::array<std::uint8_t, ReadSize> read_file(const std::string& filename) {
	const auto fileData = read_file(filename);
	assert(fileData.size() == ReadSize);
	std::array<std::uint8_t, ReadSize> result{};
	std::copy(fileData.begin(), fileData.end(), result.begin());
	return result;
}
