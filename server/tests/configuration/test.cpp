#include "test.hpp"
#include "certificates.hpp"
#include "public-protocol.hpp"
#include "wireguard.hpp"

#include <Poco/Net/SocketAddress.h>
#include <limits>
#include <thread>

extern "C" {
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <wireguard.h>
}

struct ConnectionDetails {
	Poco::Net::SocketAddress parentAddress;
	PublicProtocol::InitialisationPacket::Hash pskHash;
	PublicProtocol::InitialisationPacket::Signature pskSignature;
	std::uint64_t referringNode;
	std::uint64_t timestamp;
};

Server::Configuration get_config(std::uint64_t id, const TestPorts& testPorts);
CertificateInfo generate_default_certificate_info(const std::string& userID);
X509_RAII generate_default_certificate(const std::string& userID,
                                       const EVP_PKEY_RAII& privateKey);
EVP_PKEY_RAII pubkey_from_private_key(const EVP_PKEY_RAII& privateKey);

void test_peerless();
void test_peers();

void test() {
	test_peerless();
	test_peers();
}

void test_peerless() {
	auto config = get_config(rand(), get_test_ports());
	auto server = get_server(config);
	auto propFile = server.get_configuration();

	using Encoder = GenericCertificateManager<char>;

	assert(propFile->getUInt64("id") == config.id);
	assert(propFile->getString("control-plane-private-key") ==
	       Encoder::encode_pem(config.controlPlanePrivateKey));
	assert(propFile->getString("mesh-public-key") ==
	       base64_encode(config.meshPublicKey).value());
	assert(propFile->getString("mesh-private-key") ==
	       base64_encode(config.meshPrivateKey).value());
	assert(propFile->getString("certificate") ==
	       Encoder::encode_pem(config.controlPlaneCertificate));
	assert(propFile->getString("public-proto-address") ==
	       config.publicProtoAddress->toString());
	assert(propFile->getString("private-proto-address") ==
	       server.get_private_proto_address().toString());
	assert(!propFile->hasProperty("parent"));

	assert(!propFile->hasProperty("key"));
	Poco::Util::MapConfiguration::Keys keys;
	propFile->keys("node", keys);
	assert(keys.empty());
}

void test_peers() {
	auto config = get_config(rand(), get_test_ports());
	const auto peerConfig = get_config(rand(), get_test_ports());
	const EVP_PKEY_RAII peerControlPlanePubkey =
	    pubkey_from_private_key(peerConfig.controlPlanePrivateKey);

	const auto peer = Node{
		.id = peerConfig.id.value(),
		.controlPlanePublicKey = peerControlPlanePubkey,
		.wireGuardPublicKey = peerConfig.meshPublicKey,
		.controlPlaneIP = AbstractWireGuardManager::get_internal_ip_address(
		    peerConfig.id.value()),
		.controlPlanePort = peerConfig.privateProtoPort.value(),
		.wireGuardHost = Host{ peerConfig.wireGuardAddress.host() },
		.wireGuardPort = peerConfig.privateProtoPort.value(),
		.controlPlaneCertificate = peerConfig.controlPlaneCertificate,
		.parent = config.id,
	};

	config.peers = { peer };
	const auto server = get_server(config);
	const auto propFile = server.get_configuration();

	using Encoder = GenericCertificateManager<char>;

	Poco::Util::MapConfiguration::Keys keys;
	propFile->keys("node", keys);
	assert(keys.size() == 1);
	assert(keys[0] == std::to_string(peerConfig.id.value()));

	const auto nodeName = "node." + keys[0];
	assert(propFile->getString(nodeName + ".control-plane-public-key") ==
	       Encoder::encode_pem(peer.controlPlanePublicKey));
	assert(propFile->getString(nodeName + ".wireguard-public-key") ==
	       base64_encode(peer.wireGuardPublicKey).value());
	assert((propFile->getString(nodeName + ".control-plane-address") ==
	        Poco::Net::SocketAddress{ peer.controlPlaneIP, peer.controlPlanePort }
	            .toString()));
	const auto wgAddress = propFile->getString(nodeName + ".wireguard-address");
	const Poco::Net::IPAddress wgIP = peer.wireGuardHost;
	const auto wgPort = peer.wireGuardPort;
	assert((wgAddress == Poco::Net::SocketAddress{ wgIP, wgPort }.toString()));
	assert(propFile->getString(nodeName + ".control-plane-certificate") ==
	       Encoder::encode_pem(peer.controlPlaneCertificate));
	assert(propFile->getUInt64(nodeName + ".parent") == config.id);
}

Server::Configuration get_config(const std::uint64_t id,
                                 const TestPorts& testPorts) {
	const auto privateKey = CertificateManager::generate_rsa_key();
	assert(privateKey);

	AbstractWireGuardManager::Key wgPrivateKey;
	AbstractWireGuardManager::Key wgPublicKey;
	{
		wg_key tempWGPrivateKey;
		wg_generate_private_key(tempWGPrivateKey);
		std::copy(std::begin(tempWGPrivateKey), std::end(tempWGPrivateKey),
		          wgPrivateKey.begin());
		wg_key tempWGPublicKey;
		wg_generate_public_key(tempWGPublicKey, tempWGPrivateKey);
		std::copy(std::begin(tempWGPublicKey), std::end(tempWGPublicKey),
		          wgPublicKey.begin());
	}
	const auto userID = base64_encode(wgPublicKey);
	assert(userID);

	const auto certificate =
	    generate_default_certificate(userID.value(), privateKey.value());

	return Server::Configuration{
		.id = id,
		.controlPlanePrivateKey = privateKey.value(),
		.meshPublicKey = wgPublicKey,
		.meshPrivateKey = {},
		.wireGuardAddress = testPorts.wireGuardAddress,
		.publicProtoAddress = testPorts.publicProtoAddress,
		.privateProtoPort = testPorts.privateProtoAddress.port(),
		.controlPlaneCertificate = certificate,
		.psk = std::nullopt,
		.pskTTL = 100,
		.clock = std::make_shared<TestClock>(std::chrono::seconds{ 123456789 }),
		.peers = {},
		.randomEngine = std::nullopt,
	};
}

CertificateInfo generate_default_certificate_info(const std::string& userID) {
	return CertificateInfo{
		.country = "UK",
		.province = "province",
		.city = "city",
		.organisation = "organisation",
		.commonName = "common-name",
		.userID = userID,
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
