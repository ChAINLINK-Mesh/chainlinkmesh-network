#include "test.hpp"

#include <iostream>

using Poco::Net::SocketAddress;

const constexpr auto TEST_HOST = "127.0.1.1";
const constexpr auto PRIVILEDGED_PORTS = 1024;

int main([[maybe_unused]] int argc, char* argv[]) {
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

ByteString read_file(const std::string& filename) {
	std::ifstream file{ filename };
	const auto fileSize = std::filesystem::file_size(filename);
	assert(fileSize < std::numeric_limits<long>::max());

	ByteString fileData(fileSize, '\0');
	file.read(reinterpret_cast<char*>(fileData.data()),
	          static_cast<long>(fileSize));
	return fileData;
}

TestPorts get_test_ports() {
	const auto maxBasePort =
	    std::numeric_limits<std::uint16_t>::max() - PRIVILEDGED_PORTS - 3;
	static auto basePort = rand() % maxBasePort + PRIVILEDGED_PORTS;
	const std::uint16_t publicPort = basePort;
	const std::uint16_t privatePort = publicPort + 1;
	const std::uint16_t wireGuardPort = privatePort + 1;

	// Increment base port, wrapping if necessary
	basePort = ((wireGuardPort - PRIVILEDGED_PORTS + 1) % maxBasePort) +
	           PRIVILEDGED_PORTS;

	return TestPorts{
		.wireGuardAddress = SocketAddress{ TEST_HOST, wireGuardPort },
		.publicProtoAddress = SocketAddress{ TEST_HOST, publicPort },
		.privateProtoAddress = SocketAddress{ TEST_HOST, privatePort },
	};
}
