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

Server::Configuration get_root_config(std::uint64_t id,
                                      const TestPorts& testPorts);
Server::Configuration get_child_config(const TestPorts& testPorts,
                                       const ConnectionDetails& parentDetails);
CertificateInfo generate_default_certificate_info(const std::string& userID);
X509_RAII generate_default_certificate(const std::string& userID,
                                       const EVP_PKEY_RAII& privateKey);

void test() {
	const auto rootID = rand();
	const auto rootPorts = get_test_ports();
	auto rootServer = get_server(get_root_config(rootID, rootPorts));
	rootServer.start();

	const auto optPSK = rootServer.get_signed_psk();
	assert(optPSK);
	const auto [timestamp, pskHash, pskSignature] = optPSK.value();

	ConnectionDetails parentDetails{
		.parentAddress = rootServer.get_public_proto_address(),
		.pskHash = pskHash,
		.pskSignature = pskSignature,
		.referringNode = rootServer.get_self().id,
		.timestamp = timestamp,
	};

	auto childServer =
	    get_server(get_child_config(get_test_ports(), parentDetails));
	childServer.start();
	std::this_thread::sleep_for(std::chrono::seconds{ 20 });
	childServer.stop();
	rootServer.stop();
}

Server::Configuration get_root_config(const std::uint64_t id,
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

Server::Configuration get_child_config(const TestPorts& testPorts,
                                       const ConnectionDetails& parentDetails) {
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

	const auto childCertificateInfo =
	    generate_default_certificate_info(userID.value());

	PublicProtocol::PublicProtocolClient client{
		PublicProtocol::PublicProtocolClient::Configuration{
		    .certInfo = childCertificateInfo,
		    .parentAddress = Host{ parentDetails.parentAddress },
		    .pskHash = parentDetails.pskHash,
		    .pskSignature = parentDetails.pskSignature,
		    .referringNode = parentDetails.referringNode,
		    .timestamp = parentDetails.timestamp,
		}
	};
	const auto response = client.connect();

	return Server::Configuration{
		.id = response.allocatedNode,
		.controlPlanePrivateKey = privateKey.value(),
		.meshPublicKey = wgPublicKey,
		.meshPrivateKey = {},
		.wireGuardAddress = testPorts.wireGuardAddress,
		.publicProtoAddress = testPorts.publicProtoAddress,
		.privateProtoPort = testPorts.privateProtoAddress.port(),
		.controlPlaneCertificate = response.signedCSR,
		.psk = std::nullopt,
		.pskTTL = 100,
		.clock = std::make_shared<TestClock>(std::chrono::seconds{ 123456789 }),
		.peers = { Node{
		    .id = response.respondingNode,
		    .controlPlanePublicKey = {},
		    .wireGuardPublicKey = response.respondingWireGuardPublicKey,
		    .controlPlaneIP = response.respondingControlPlaneIPAddress,
		    .controlPlanePort = response.respondingControlPlanePort,
		    .wireGuardHost = client.get_parent_address(response),
		    .wireGuardPort = response.respondingWireGuardPort,
		    .controlPlaneCertificate = {},
		} },
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
