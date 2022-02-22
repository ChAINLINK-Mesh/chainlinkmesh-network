#include "certificates.hpp"
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

	std::clog << "Running test \'" << argv[0] << "\':\n";

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

Server get_server(const Server::Configuration& config) {
	const auto privateKeyBytes = read_file("legitimate-ca-key.pem");
	auto privateKey = CertificateManager::decode_pem_private_key(privateKeyBytes);
	assert(privateKey.has_value());
	return Server{ config, std::move(privateKey.value()) };
}

TestPorts get_test_ports() {
	const std::uint16_t publicPort =
	    rand() %
	        (std::numeric_limits<std::uint16_t>::max() - PRIVILEDGED_PORTS - 3) +
	    PRIVILEDGED_PORTS;
	const std::uint16_t privatePort = publicPort + 1;
	const std::uint16_t wireGuardPort = privatePort + 1;

	std::clog << "Using ports " << publicPort << "-" << wireGuardPort
	          << " for testing\n";

	return TestPorts{
		.wireGuardAddress = SocketAddress{ TEST_HOST, wireGuardPort },
		.publicProtoAddress = SocketAddress{ TEST_HOST, publicPort },
		.privateProtoAddress = SocketAddress{ TEST_HOST, privatePort },
	};
}
