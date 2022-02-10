#include "test.hpp"
#include <Poco/Net/SocketAddress.h>
#include <cassert>
#include <fstream>
#include <iostream>
#include <limits>

using Poco::Net::SocketAddress;

const constexpr auto TEST_HOST = "127.0.1.1";
const constexpr auto PRIVILEDGED_PORTS = 1024;

int main(int argc, char* argv[]) {
	assert(argc > 0);

	const std::uint16_t publicPort =
	    rand() %
	        (std::numeric_limits<std::uint16_t>::max() - PRIVILEDGED_PORTS - 3) +
	    PRIVILEDGED_PORTS;
	const std::uint16_t privatePort = publicPort + 1;
	const std::uint16_t wireGuardPort = privatePort + 1;

	std::clog << "Running test \'" << argv[0] << "\':\n";
	std::clog << "Using ports " << publicPort << "-" << wireGuardPort
	          << " for testing\n";

	const TestPorts testPorts{
		.wireGuardAddress = SocketAddress{ TEST_HOST, wireGuardPort },
		.publicProtoAddress = SocketAddress{ TEST_HOST, publicPort },
		.privateProtoAddress = SocketAddress{ TEST_HOST, privatePort },
	};

	Server server{ get_config(testPorts) };

	try {
		test(server);
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
