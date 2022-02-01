#include <cassert>
#include <filesystem>
#include <fstream>
#include <openssl/pem.h>
#include <public-protocol.hpp>
#include <string>
#include <test.hpp>

using namespace PublicProtocol;
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
		throw "Equality comparison is not working for similar packets";
	}

	// Wrong timestamp.
	packet2.timestamp = 123ULL;

	if (packet1 == packet2) {
		throw "Equality comparison is not working for invalid timestamp";
	}

	// Wrong CSR.
	packet2.timestamp = 123456789ULL;
	auto* subjectName{ X509_REQ_get_subject_name(packet2.csr.get()) };
	auto* newName{ X509_NAME_dup(subjectName) };
	unsigned char newLocality[] = "New locality";
	if (X509_NAME_add_entry_by_txt(newName, "L", MBSTRING_UTF8, newLocality,
	                               sizeof(newLocality) - 1, -1, 0) < 0) {
		throw "Failed to add entry to subject name";
	}
	X509_REQ_set_subject_name(packet2.csr.get(), newName);

	if (packet1 == packet2) {
		throw "Equality comparison is not working for invalid csr";
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
		.csr = CertificateManager::decode_pem_csr(read_file("legitimate-csr.csr"))
		           .value(),
	};
}

PublicProtocolManager get_testing_protocol_manager() {
	PublicProtocolManager protocolManager{
		"TestingKey",
		Node{
		    .id = 987654321ULL,
		    .publicKey = read_file("legitimate-ca-pubkey.pem"),
		    .meshIP = Poco::Net::IPAddress{ "10.0.0.1" },
		    .wireguardIP = Poco::Net::IPAddress{ "127.0.0.1" },
		    .controlPlanePort = Node::DEFAULT_CONTROL_PLANE_PORT,
		    .wireguardPort = Node::DEFAULT_WIREGUARD_PORT,
		}
	};

	return protocolManager;
}
