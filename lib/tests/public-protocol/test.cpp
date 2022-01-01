#include <cassert>
#include <filesystem>
#include <fstream>
#include <public-protocol.hpp>
#include <string>

template <size_t ReadSize>
std::array<std::uint8_t, ReadSize> read_file(const std::string& filename);

std::string read_file(const std::string& filename);

void test_equality();
void test_legitimate_packet();

void test() {
	test_equality();
	test_legitimate_packet();
}

// Testing equality comparison
void test_equality() {
	const InitialisationPacket packet1 = {
		.timestamp = 123456789ULL,
		.timestampPSKHash = read_file<SHA256_DIGEST_SIZE>("legitimate-psk.sha256"),
		.referringNode = 987654321ULL,
		.timestampPSKSignature =
		    read_file<SHA256_SIGNATURE_SIZE>("legitimate-psk-signature.sha256"),
		.csr = read_file("legitimate-csr.csr"),
	};

	InitialisationPacket packet2 = {
		.timestamp = 123456789ULL,
		.timestampPSKHash = read_file<SHA256_DIGEST_SIZE>("legitimate-psk.sha256"),
		.referringNode = 987654321ULL,
		.timestampPSKSignature =
		    read_file<SHA256_SIGNATURE_SIZE>("legitimate-psk-signature.sha256"),
		.csr = read_file("legitimate-csr.csr"),
	};

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
	const InitialisationPacket testPacket = {
		.timestamp = 123456789ULL,
		.timestampPSKHash = read_file<SHA256_DIGEST_SIZE>("legitimate-psk.sha256"),
		.referringNode = 987654321ULL,
		.timestampPSKSignature =
		    read_file<SHA256_SIGNATURE_SIZE>("legitimate-psk-signature.sha256"),
		.csr = read_file("legitimate-csr.csr"),
	};

	const auto filePacket = read_file("legitimate-packet.data");

	if (auto packet = ConnectionHandler::decode_packet(
	        { filePacket.data(), filePacket.size() });
	    !packet || packet.value() != testPacket) {
		throw "Failed to decode valid packet";
	}
}

std::string read_file(const std::string& filename) {
	std::ifstream file{ filename };
	const auto fileSize = std::filesystem::file_size(filename);
	assert(fileSize < std::numeric_limits<long>::max());

	std::string fileData(fileSize, '\0');
	file.read(fileData.data(), fileSize);
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
