#include "test.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
	assert(argc > 0);

	std::clog << "Running test \'" << argv[0] << "\': ";

	try {
		test();
		std::clog << "Success\n";
	} catch (const char* error) {
		std::clog << "Failure: " << error << "\n";
		throw;
	} catch (const std::string& error) {
		std::clog << "Failure: " << error << "\n";
		throw;
	}
}

std::string read_file(const std::string& filename) {
	std::ifstream file{ filename };
	const auto fileSize = std::filesystem::file_size(filename);
	assert(fileSize < std::numeric_limits<long>::max());

	std::string fileData(fileSize, '\0');
	file.read(fileData.data(), static_cast<long>(fileSize));
	return fileData;
}
