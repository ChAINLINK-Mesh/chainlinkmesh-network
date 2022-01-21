#include <cassert>
#include <filesystem>
#include <fstream>
#include <public-protocol.hpp>
#include <string>

using namespace PublicProtocol;

template <size_t ReadSize>
std::array<std::uint8_t, ReadSize> read_file(const std::string& filename);

std::string read_file(const std::string& filename);
PublicProtocolManager get_testing_protocol_manager();
InitialisationPacket get_legitimate_packet();

void test_equality();
void test_legitimate_packet();
void test_invalid_psk_hash();
void test_unknown_referring_node();
void test_invalid_psk_signature();

void test() {
	test_equality();
	test_legitimate_packet();
	test_invalid_psk_hash();
	test_unknown_referring_node();
	test_invalid_psk_signature();
}

// Testing equality comparison
void test_equality() {
	const InitialisationPacket packet1 = get_legitimate_packet();
	InitialisationPacket packet2 = get_legitimate_packet();

	if (packet1 != packet2) {
		throw "Equality comparison is not working";
	}

	// Wrong timestamp.
	packet2.timestamp = 123ULL;

	if (packet1 == packet2) {
		throw "Equality comparison is not working for invalid timestamp";
	}

	// Wrong CSR.
	packet2.timestamp = 123456789ULL;
	packet2.csr = packet2.csr.substr(0, packet2.csr.size() - 1);

	if (packet1 == packet2) {
		throw "Equality comparison is not working";
	}
}

// Legitimate PSK signature
void test_legitimate_packet() {
	const InitialisationPacket truePacket = get_legitimate_packet();

	const auto filePacket = read_file("legitimate-packet.data");

	if (auto packet = get_testing_protocol_manager().decode_packet(filePacket);
	    !packet || packet.value() != truePacket) {
		throw "Failed to decode valid packet";
	}
}

void test_invalid_psk_hash() {
	const auto invalidPSKHashPacket = read_file("invalid-psk-packet.data");

	if (get_testing_protocol_manager().decode_packet(invalidPSKHashPacket)) {
		throw "Incorrectly decoded packet with invalid PSK";
	}
}

void test_unknown_referring_node() {
	const auto unknownReferringNodePacket =
	    read_file("unknown-referring-node.data");

	if (get_testing_protocol_manager().decode_packet(
	        unknownReferringNodePacket)) {
		throw "Incorrectly decoded packet with invalid referring node";
	}
}

void test_invalid_psk_signature() {
	const auto invalidPSKSignaturePacket =
	    read_file("invalid-psk-signature-packet.data");

	if (get_testing_protocol_manager().decode_packet(invalidPSKSignaturePacket)) {
		throw "Incorrectly decoded packet with invalid signature";
	}
}

InitialisationPacket get_legitimate_packet() {
	return InitialisationPacket{
		.timestamp = 123456789ULL,
		.timestampPSKHash = read_file<SHA256_DIGEST_SIZE>("legitimate-psk.sha256"),
		.referringNode = 987654321ULL,
		.timestampPSKSignature =
		    read_file<SHA256_SIGNATURE_SIZE>("legitimate-psk-signature.sha256"),
		.csr = read_file("legitimate-csr.csr"),
	};
}

std::string read_file(const std::string& filename) {
	std::ifstream file{ filename };
	const auto fileSize = std::filesystem::file_size(filename);
	assert(fileSize < std::numeric_limits<long>::max());

	std::string fileData(fileSize, '\0');
	file.read(fileData.data(), fileSize);
	return fileData;
}

PublicProtocolManager get_testing_protocol_manager() {
	PublicProtocolManager protocolManager{
		"TestingKey",
		Node{
		    .id = 987654321ULL,
		    .publicKey = read_file("legitimate-ca-pubkey.pem"),
		    .meshIP = Poco::Net::IPAddress{ "127.0.0.1" },
		}
	};

	return protocolManager;
}

template <size_t ReadSize>
std::array<std::uint8_t, ReadSize> read_file(const std::string& filename) {
	const auto fileData = read_file(filename);
	assert(fileData.size() == ReadSize);
	std::array<std::uint8_t, ReadSize> result{};
	std::copy(fileData.begin(), fileData.end(), result.begin());
	return result;
}
