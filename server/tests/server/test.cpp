#include "test.hpp"
#include "certificates.hpp"
#include "literals.hpp"
#include "node.hpp"
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
Server::Configuration get_child_config(const TestPorts& testPorts,
                                       const ConnectionDetails& parentDetails);
CertificateInfo
generate_default_certificate_info(std::optional<std::uint64_t> nodeID,
                                  const std::string& userID);
X509_RAII generate_default_certificate(std::uint64_t nodeID,
                                       const std::string& wireguardPublicKey,
                                       const EVP_PKEY_RAII& privateKey);

void test() {
	const auto rootID = rand();
	const auto rootPorts = get_test_ports();
	auto rootServer = get_server(get_config(rootID, rootPorts));
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
	// TODO: Convert this static sleep into a wait for an actual connection.
	std::this_thread::sleep_for(std::chrono::seconds{ 2 });
	childServer.stop();
	rootServer.stop();
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
	    generate_default_certificate(id, userID.value(), privateKey.value());

	return Server::Configuration{
		.id = id,
		.parent = std::nullopt,
		.controlPlanePrivateKey = privateKey.value(),
		.meshPublicKey = wgPublicKey,
		.meshPrivateKey = wgPrivateKey,
		.wireGuardAddress = testPorts.wireGuardAddress,
		.publicProtoAddress = testPorts.publicProtoAddress,
		.privateProtoPort = testPorts.privateProtoAddress.port(),
		.controlPlaneCertificate = certificate,
		.psk = "A testing PSK"_uc,
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
	    generate_default_certificate_info(std::nullopt, userID.value());

	PublicProtocol::PublicProtocolClient client{
		PublicProtocol::PublicProtocolClient::Configuration{
		    .certInfo = childCertificateInfo,
		    .privateKey = privateKey.value(),
		    .parentAddress = Host{ parentDetails.parentAddress },
		    .pskHash = parentDetails.pskHash,
		    .pskSignature = parentDetails.pskSignature,
		    .referringNode = parentDetails.referringNode,
		    .timestamp = parentDetails.timestamp,
		}
	};
	const auto response = client.connect();

	if (response.certificateChain.size() != 2) {
		throw std::runtime_error{
			"Certificate chain doesn't include parent and child certificates"
		};
	}

	const auto& parentCert = response.certificateChain[0];
	const auto& childCert = response.certificateChain[1];
	const auto parentPublicKey =
	    CertificateManager::get_certificate_pubkey(parentCert);

	// We're not testing the certificate manager here.
	assert(parentPublicKey.has_value());

	return Server::Configuration{
		.id = response.allocatedNode,
		.parent = std::nullopt,
		.controlPlanePrivateKey = privateKey.value(),
		.meshPublicKey = wgPublicKey,
		.meshPrivateKey = wgPrivateKey,
		.wireGuardAddress = testPorts.wireGuardAddress,
		.publicProtoAddress = testPorts.publicProtoAddress,
		.privateProtoPort = testPorts.privateProtoAddress.port(),
		.controlPlaneCertificate = childCert,
		.psk = std::nullopt,
		.pskTTL = 100,
		.clock = std::make_shared<TestClock>(std::chrono::seconds{ 123456789 }),
		.peers = { Node{
		    .id = response.respondingNode,
		    .controlPlanePublicKey = parentPublicKey.value(),
		    .wireGuardPublicKey = response.respondingWireGuardPublicKey,
		    .controlPlaneIP = response.respondingControlPlaneIPAddress,
		    .connectionDetails =
		        NodeConnection{
		            .controlPlanePort = response.respondingControlPlanePort,
		            .wireGuardHost = client.get_parent_address(response),
		        },
		    .controlPlaneCertificate = parentCert,
		    .parent = std::nullopt,
		} },
		.randomEngine = std::nullopt,
	};
}

CertificateInfo
generate_default_certificate_info(std::optional<std::uint64_t> nodeID,
                                  const std::string& userID) {
	return CertificateInfo{
		.country = "UK",
		.province = "province",
		.city = "city",
		.organisation = "organisation",
		.commonName = "common-name",
		.userID = userID,
		.serialNumber = nodeID,
		.validityDuration = PublicProtocol::PublicProtocolManager::
		    DEFAULT_CERTIFICATE_VALIDITY_SECONDS,
	};
}

X509_RAII
generate_default_certificate(const std::uint64_t nodeID,
                             const std::string& wireguardPublicKey,
                             const EVP_PKEY_RAII& privateKey) {
	auto certificate = CertificateManager::generate_certificate(
	    generate_default_certificate_info(nodeID, wireguardPublicKey),
	    privateKey);

	assert(certificate);
	return certificate.value();
}
