#include "test.hpp"
#include "certificates.hpp"
#include "node.hpp"
#include "peers.hpp"
#include "public-protocol.hpp"
#include "wireguard.hpp"

#include <Poco/Net/SocketAddress.h>

extern "C" {
#include <openssl/bio.h>
#include <openssl/pem.h>
}

AbstractWireGuardManager::Key generate_mock_wg_key();
CertificateInfo generate_default_certificate_info(const std::string& userID);
X509_RAII generate_default_certificate(const std::string& userID,
                                       const EVP_PKEY_RAII& privateKey);
EVP_PKEY_RAII pubkey_from_private_key(const EVP_PKEY_RAII& privateKey);
Node get_random_peer(std::optional<std::uint64_t> parentID);

void create_peers();
void get_peers();
void add_peers();
void delete_peers();
void get_certificate_chain();

void test() {
	create_peers();
	get_peers();
	add_peers();
	delete_peers();
	get_certificate_chain();
}

void create_peers() {
	[[maybe_unused]] Peers peers{};

	[[maybe_unused]] Peers vectorPeers{ std::vector{
		  get_random_peer(std::nullopt) } };

	[[maybe_unused]] Peers otherPeers{ vectorPeers };

	[[maybe_unused]] Peers movedPeers{ std::move(vectorPeers) };
}

void get_peers() {
	const auto randPeer = get_random_peer(std::nullopt);
	Peers vectorPeers{ std::vector{ randPeer } };

	if (vectorPeers.get_peers().size() != 1) {
		throw "Peers::get_peers() has wrong number of peer nodes";
	}

	if (!vectorPeers.get_peer(randPeer.id).has_value()) {
		throw "Peers::get_peer(std::uint64_t nodeID) failed to find known peer "
		      "node";
	}

	// Try getting an unknown peer ID
	if (vectorPeers.get_peer(randPeer.id + 1).has_value()) {
		throw "Peers::get_peer(std::uint64_t nodeID) finds unknown peer node";
	}
}

void add_peers() {
	Peers peers{};

	const auto randPeer = get_random_peer(std::nullopt);

	if (!peers.add_peer(randPeer)) {
		throw "Peers::add_peer(Node node) didn't add unique peer node";
	}

	if (!peers.get_peer(randPeer.id).has_value()) {
		throw "Cannot get peer added by Peers::add_peer(Node node)";
	}

	if (peers.add_peer(randPeer)) {
		throw "Peers::add_peer(Node node) incorrectly reports success adding "
		      "duplicate node";
	}
}

void delete_peers() {
	const auto randPeer = get_random_peer(std::nullopt);
	Peers peers{ std::vector{ randPeer } };

	if (!peers.delete_peer(randPeer.id)) {
		throw "Peers::delete_peer(std::uint64_t nodeID) failed to delete valid "
		      "peer";
	}

	if (!peers.get_peers().empty()) {
		throw "Peers still contains deleted peer nodes";
	}

	// Try deleting unknown peer ID.
	try {
		if (peers.delete_peer(randPeer.id + 1)) {
			throw "Incorrectly reported successful deletion of invalid peer";
		}
	} catch (char /* forwarded */[]) {
		throw;
	} catch (...) {
		throw "Peers throws deleting unknown peer node";
	}
}

void get_certificate_chain() {
	const auto rootPeer = get_random_peer(std::nullopt);
	const auto childPeer = get_random_peer(rootPeer.id);
	const auto otherPeer = get_random_peer(rootPeer.id);
	const auto grandchildPeer = get_random_peer(childPeer.id);

	Peers peers{ std::vector{ rootPeer, childPeer, otherPeer, grandchildPeer } };

	const auto certificateChain = peers.get_certificate_chain(childPeer.id);

	if (!certificateChain) {
		throw "Certificate chain missing for valid peer";
	}

	if (certificateChain->size() != 2) {
		throw "Certificate chain has the wrong number of certificates";
	}

	if (*certificateChain->at(0) != *rootPeer.controlPlaneCertificate.get()) {
		throw "Certificate chain's first certificate is not root CA certificate";
	}

	if (*certificateChain->at(1) != *childPeer.controlPlaneCertificate.get()) {
		throw "Certificate chain's second certificate is not child certificate";
	}
}

AbstractWireGuardManager::Key generate_mock_wg_key() {
	AbstractWireGuardManager::Key mockKey{};

	for (auto& byte : mockKey) {
		byte = rand();
	}

	return mockKey;
}

CertificateInfo generate_default_certificate_info(const std::string& userID) {
	return CertificateInfo{
		.country = "UK",
		.province = "province",
		.city = "city",
		.organisation = "organisation",
		.commonName = "common-name",
		.userID = userID,
		.serialNumber = "123456789",
		.validityDuration = PublicProtocol::PublicProtocolManager::
		    DEFAULT_CERTIFICATE_VALIDITY_SECONDS,
	};
}

X509_RAII
generate_default_certificate(const std::string& userID,
                             const EVP_PKEY_RAII& privateKey) {
	auto certificate = CertificateManager::generate_certificate(
	    generate_default_certificate_info(userID), privateKey);

	assert(certificate);
	return certificate.value();
}

EVP_PKEY_RAII pubkey_from_private_key(const EVP_PKEY_RAII& privateKey) {
	BIO_RAII bio{ BIO_new(BIO_s_mem()) };
	assert(bio);
	assert(PEM_write_bio_PUBKEY(bio.get(), privateKey.get()) != 0);
	EVP_PKEY* pubkey{};
	assert(PEM_read_bio_PUBKEY(bio.get(), &pubkey, nullptr, nullptr) != nullptr);

	return pubkey;
}

Node get_random_peer(std::optional<std::uint64_t> parentID) {
	const std::uint64_t id = rand();
	const auto testPorts = get_test_ports();

	const auto privateKey = CertificateManager::generate_rsa_key();
	assert(privateKey);

	AbstractWireGuardManager::Key wgPublicKey = generate_mock_wg_key();

	const auto userID = base64_encode(wgPublicKey);
	assert(userID);

	const auto certificate =
	    generate_default_certificate(userID.value(), privateKey.value());

	const EVP_PKEY_RAII peerControlPlanePubkey =
	    pubkey_from_private_key(privateKey.value());

	return Node{
		.id = id,
		.controlPlanePublicKey = peerControlPlanePubkey,
		.wireGuardPublicKey = wgPublicKey,
		.controlPlaneIP = Node::get_control_plane_ip(id),
		.connectionDetails =
		    NodeConnection{
		        .controlPlanePort = testPorts.privateProtoAddress.port(),
		        .wireGuardHost = Host{ testPorts.wireGuardAddress },
		        .wireGuardPort = testPorts.wireGuardAddress.port(),
		    },
		.controlPlaneCertificate = certificate,
		.parent = parentID,
	};
}
