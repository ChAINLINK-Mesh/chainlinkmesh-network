#include "certificates.hpp"
#include "clock.hpp"
#include "literals.hpp"
#include "peers.hpp"
#include "private-protocol.hpp"
#include "public-protocol.hpp"
#include "wireguard.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <test.hpp>
#include <utility>

extern "C" {
#include <openssl/pem.h>
}

using namespace PublicProtocol;
SelfNode get_self_node();
PrivateProtocol::PrivateProtocolManager
get_private_protocol_manager(SelfNode selfNode);
PublicProtocolManager get_public_protocol_manager(
    SelfNode selfNode,
    PrivateProtocol::PrivateProtocolManager& privateProtocolManager);
std::tuple<PrivateProtocol::PrivateProtocolManager, PublicProtocolManager>
get_testing_context();
InitialisationPacket get_legitimate_packet();

void test_equality();
void test_legitimate_packet();
void test_invalid_psk_hash();
void test_unknown_referring_node();
void test_invalid_psk_signature();
void test_legitimate_response_packet();

void test() {
	test_equality();
	test_legitimate_packet();
	test_invalid_psk_hash();
	test_unknown_referring_node();
	test_invalid_psk_signature();
	test_legitimate_response_packet();
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
	auto [privateProtocolManager, publicProtocolManager] = get_testing_context();

	if (auto packet = publicProtocolManager.decode_packet(filePacket);
	    !packet || packet.value() != truePacket) {
		throw "Failed to decode valid packet";
	}
}

void test_invalid_psk_hash() {
	const auto invalidPSKHashPacket = read_file("invalid-psk-packet.data");
	auto [privateProtocolManager, publicProtocolManager] = get_testing_context();

	if (publicProtocolManager.decode_packet(invalidPSKHashPacket)) {
		throw "Incorrectly decoded packet with invalid PSK";
	}
}

void test_unknown_referring_node() {
	const auto unknownReferringNodePacket =
	    read_file("unknown-referring-node.data");
	auto [privateProtocolManager, publicProtocolManager] = get_testing_context();

	if (publicProtocolManager.decode_packet(unknownReferringNodePacket)) {
		throw "Incorrectly decoded packet with invalid referring node";
	}
}

void test_invalid_psk_signature() {
	const auto invalidPSKSignaturePacket =
	    read_file("invalid-psk-signature-packet.data");
	auto [privateProtocolManager, publicProtocolManager] = get_testing_context();

	if (publicProtocolManager.decode_packet(invalidPSKSignaturePacket)) {
		throw "Incorrectly decoded packet with invalid signature";
	}
}

void test_legitimate_response_packet() {
	const auto legitimateResponsePacketBytes =
	    read_file("legitimate-response-packet.data");

	if (const auto legitimateResponsePacket =
	        InitialisationRespPacket::decode_bytes(
	            legitimateResponsePacketBytes)) {
		if (legitimateResponsePacket->respondingNode != 987654321ULL) {
			throw "Failed to decode legitimate response packet's responding node";
		}

		if (legitimateResponsePacket->allocatedNode != 1223334444ULL) {
			throw "Failed to decode legitimate reponse packet's allocated node";
		}

		if (const auto& rWGPK =
		        legitimateResponsePacket->respondingWireGuardPublicKey;
		    !std::equal(rWGPK.begin(), rWGPK.end(),
		                read_file("wireguard-pubkey.data").begin())) {
			throw "Failed to decode legitimate response packet's responding "
			      "WireGuard public key";
		}
	} else {
		throw "Failed to decode legitimate response packet";
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

SelfNode get_self_node() {
	const auto wireguardPubkeyFile = trim(read_file("wireguard-pubkey.key"));
	const auto wireguardPubkeyBytes = base64_decode(wireguardPubkeyFile);
	assert(wireguardPubkeyBytes.has_value());
	AbstractWireGuardManager::Key wireguardPubkey{};
	std::copy(wireguardPubkeyBytes->begin(), wireguardPubkeyBytes->end(),
	          wireguardPubkey.begin());
	const auto wireguardPrivkeyFile = trim(read_file("wireguard-privkey.key"));
	const auto wireguardPrivkeyBytes = base64_decode(wireguardPrivkeyFile);
	assert(wireguardPrivkeyBytes.has_value());
	AbstractWireGuardManager::Key wireguardPrivkey{};
	std::copy(wireguardPrivkeyBytes->begin(), wireguardPrivkeyBytes->end(),
	          wireguardPrivkey.begin());
	const auto certificateBytes = read_file("legitimate-ca.pem");
	const auto certificate =
	    CertificateManager::decode_pem_certificate(certificateBytes);
	assert(certificate.has_value());

	const auto privateKeyBytes = read_file("legitimate-ca-key.pem");
	auto privateKey = CertificateManager::decode_pem_private_key(privateKeyBytes);
	assert(privateKey.has_value());

	return SelfNode{
		Node{
		    .id = 987654321ULL,
		    .controlPlanePublicKey = privateKey.value(),
		    .wireGuardPublicKey = wireguardPubkey,
		    .controlPlaneIP = Poco::Net::IPAddress{ "10.0.0.1" },
		    .connectionDetails =
		        NodeConnection{
		            .controlPlanePort = PrivateProtocol::DEFAULT_CONTROL_PLANE_PORT,
		            .wireGuardHost = Host{ "127.0.0.1", Node::DEFAULT_WIREGUARD_PORT },
		        },
		    .controlPlaneCertificate = certificate.value(),
		    .parent = std::nullopt,
		},
		privateKey.value(),
		wireguardPrivkey,
		ByteString{ "Testing Key"_uc },
		100,
	};
}

PrivateProtocol::PrivateProtocolManager
get_private_protocol_manager(SelfNode selfNode) {
	return PrivateProtocol::PrivateProtocolManager{
		PrivateProtocol::PrivateProtocolManager::Configuration{
		    .controlPlanePort = PrivateProtocol::DEFAULT_CONTROL_PLANE_PORT,
		    .selfNode = std::move(selfNode),
		    .peers = std::make_shared<Peers>(),
		}
	};
}

PublicProtocolManager get_public_protocol_manager(
    SelfNode selfNode,
    PrivateProtocol::PrivateProtocolManager& privateProtocolManager) {
	return PublicProtocolManager{ PublicProtocolManager::Configuration{
		  .self = std::move(selfNode),
		  .clock = std::make_shared<TestClock>(std::chrono::seconds{
		      123456789 }), // I.e. the same second the PSK was generated
		  .peers = std::make_shared<Peers>(),
		  .privateProtocolManager = privateProtocolManager,
		  .randomEngine = std::default_random_engine{ std::random_device{}() },
	} };
}

std::tuple<PrivateProtocol::PrivateProtocolManager, PublicProtocolManager>
get_testing_context() {
	const auto selfNode = get_self_node();
	auto privateProtocolManager = get_private_protocol_manager(selfNode);
	auto publicProtocolManager =
	    get_public_protocol_manager(selfNode, privateProtocolManager);
	return { privateProtocolManager, publicProtocolManager };
}
