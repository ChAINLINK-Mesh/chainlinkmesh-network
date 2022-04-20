#include "test.hpp"
#include "certificates.hpp"
#include "types.hpp"
#include "wireguard.hpp"

#include <Poco/FIFOBuffer.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/StreamSocket.h>
#include <cassert>
#include <chrono>
#include <limits>
#include <thread>

extern "C" {
#include <openssl/bio.h>
#include <openssl/pem.h>
}

void check_open_status(Server& server);
Server::Configuration get_config(const TestPorts& testPorts);

void test() {
	auto server = get_server(get_config(get_test_ports()));
	check_open_status(server);
}

void check_open_status(Server& server) {
	server.start();

	Poco::Net::StreamSocket publicSocket{};

	try {
		publicSocket.connect(server.get_public_proto_address());
	} catch (Poco::Net::ConnectionRefusedException& e) {
		throw "Failed to connect to server's public protocol: " + e.message();
	}
	const auto legitimatePacket = read_file("legitimate-init-packet.data");

	assert(legitimatePacket.size() < std::numeric_limits<int>::max());

	publicSocket.sendBytes(legitimatePacket.data(),
	                       static_cast<int>(legitimatePacket.size()), 0);

	Poco::FIFOBuffer receiveBuf{ 1024 };
	publicSocket.receiveBytes(receiveBuf);

	if (receiveBuf.isEmpty()) {
		throw "Public protocol did not respond to valid initialisation request";
	}

	server.stop();
}

Server::Configuration get_config(const TestPorts& testPorts) {
	const auto controlPlanePrivateKeyBytes =
	    read_file("legitimate-ca-key.pem");
	auto controlPlanePrivateKey =
	    CertificateManager::decode_pem_private_key(controlPlanePrivateKeyBytes);
	assert(controlPlanePrivateKey);

	const auto wireGuardPublicKeyBytes =
	    base64_decode(trim(read_file("wireguard-pubkey.key")));
	assert(wireGuardPublicKeyBytes.has_value());

	AbstractWireGuardManager::Key wireGuardPublicKey{};
	assert(wireGuardPublicKeyBytes->size() == wireGuardPublicKey.size());
	std::copy(wireGuardPublicKeyBytes->begin(), wireGuardPublicKeyBytes->end(),
	          wireGuardPublicKey.begin());

	const auto caCertBytes = read_file("legitimate-ca.pem");
	assert(caCertBytes.size() < std::numeric_limits<int>::max());
	BIO_RAII caCertBio{ BIO_new_mem_buf(caCertBytes.data(),
		                                  static_cast<int>(caCertBytes.size())) };
	assert(caCertBio);

	return Server::Configuration{
		.id = 987654321,
		.controlPlanePrivateKey = controlPlanePrivateKey.value(),
		.meshPublicKey = wireGuardPublicKey,
		.meshPrivateKey = {},
		.wireGuardAddress = testPorts.wireGuardAddress,
		.publicProtoAddress = testPorts.publicProtoAddress,
		.privateProtoPort = testPorts.privateProtoAddress.port(),
		.controlPlaneCertificate = X509_RAII{ PEM_read_bio_X509(
		    caCertBio.get(), nullptr, nullptr, nullptr) },
		.psk = std::nullopt,
		.pskTTL = 100,
		.clock = std::make_shared<TestClock>(
		    std::chrono::seconds{ 123456789 }), // i.e. the same second the PSK was
		                                        // generated
		.peers = {},
		.randomEngine = std::nullopt,
	};
}
