#include "test.hpp"
#include <Poco/FIFOBuffer.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/StreamSocket.h>
#include <cassert>
#include <chrono>
#include <limits>
#include <thread>

void check_open_status(Server& server);

void test(Server& server) {
	check_open_status(server);
}

void check_open_status(Server& server) {
	auto serverExecution = server.start();

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

	serverExecution.stop();
}

Server::Configuration get_config(const TestPorts& testPorts) {
	const auto controlPlanePublicKey = read_file("legitimate-ca-pubkey.pem");
	const auto wireGuardPublicKeyBytes =
	    base64_decode(trim(read_file("wireguard-pubkey.key")));
	assert(wireGuardPublicKeyBytes.has_value());

	Node::WireGuardPublicKey wireGuardPublicKey{};
	assert(wireGuardPublicKeyBytes->size() == wireGuardPublicKey.size());
	std::copy(wireGuardPublicKeyBytes->begin(), wireGuardPublicKeyBytes->end(),
	          wireGuardPublicKey.begin());

	return Server::Configuration{
		.id = 987654321,
		.controlPlanePublicKey = controlPlanePublicKey,
		.meshPublicKey = wireGuardPublicKey,
		.wireGuardAddress = testPorts.wireGuardAddress,
		.publicProtoAddress = testPorts.publicProtoAddress,
		.privateProtoAddress = testPorts.privateProtoAddress,
	};
}
