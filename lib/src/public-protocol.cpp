#include "public-protocol.hpp"
#include "certificates.hpp"
#include "literals.hpp"
#include "types.hpp"
#include "utilities.hpp"
#include "wireguard.hpp"

#include <Poco/ByteOrder.h>
#include <Poco/Exception.h>
#include <Poco/Net/DNS.h>
#include <Poco/Net/IPAddress.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/TCPServer.h>
#include <cassert>
#include <chrono>
#include <ios>
#include <iostream>
#include <limits>
#include <random>
#include <stdexcept>
#include <utility>
#include <variant>

extern "C" {
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
}

using namespace PublicProtocol;

PublicProtocolManager::PublicProtocolManager(Configuration config)
    : selfNode{ std::move(config.self) }, clock{ config.clock },
      idDistribution{ Node::generate_id_range() },
      randomEngine{ config.randomEngine }, peers{ config.peers },
      privateProtocolManager{ config.privateProtocolManager } {
	assert(selfNode.connectionDetails);
	// Ensure that the current node's host is specified as a valid address.
	assert(selfNode.connectionDetails->wireGuardHost);
	assert(peers);

	this->peers->add_peer(selfNode);
}

std::unique_ptr<Poco::Net::TCPServer>
PublicProtocolManager::start(const Poco::Net::ServerSocket& serverSocket,
                             Poco::Net::TCPServerParams::Ptr params) {
	auto server = std::make_unique<Poco::Net::TCPServer>(
	    new ConnectionFactory(*this), serverSocket, std::move(params));
	server->start();

	return server;
}

std::optional<InitialisationPacket>
PublicProtocolManager::decode_packet(BufferType& buffer) const {
	InitialisationPacket packet{};

	{
		const auto read = buffer.read(reinterpret_cast<char*>(&packet.timestamp),
		                              sizeof(packet.timestamp));

		if (read != sizeof(packet.timestamp)) {
			return std::nullopt;
		}

		packet.timestamp = Poco::ByteOrder::fromLittleEndian(packet.timestamp);
		const std::uint64_t now =
		    std::chrono::time_point_cast<std::chrono::seconds>(this->clock->now())
		        .time_since_epoch()
		        .count();
		const auto pskExpiryTime = packet.timestamp + this->selfNode.pskTTL;

		if (now > pskExpiryTime || now < packet.timestamp) {
			std::cerr << "Initialisation request had an invalid timestamp ("
			          << packet.timestamp << ")\n";
			return std::nullopt;
		}
	}

	{
		std::array<char, SHA256_DIGEST_SIZE> digest{};
		const auto read = buffer.read(digest.data(), SHA256_DIGEST_SIZE);

		if (read != SHA256_DIGEST_SIZE) {
			return std::nullopt;
		}

		// Re-compute timestamp-PSK hash and compare
		const auto timestampPSK =
		    get_bytestring(packet.timestamp) +
		    ByteString{ this->selfNode.psk.begin(), this->selfNode.psk.end() };
		std::array<std::int8_t, EVP_MAX_MD_SIZE> timestampPSKRehash{};
		unsigned int rehashSize = 0;

		// Failed to compute SHA-256 digest
		if (EVP_Digest(timestampPSK.data(), timestampPSK.size(),
		               reinterpret_cast<std::uint8_t*>(timestampPSKRehash.data()),
		               &rehashSize, EVP_sha256(), nullptr) == 0 ||
		    rehashSize != SHA256_DIGEST_SIZE) {
			return std::nullopt;
		}

		// Calculated digest was incorrect. I.e. the PSK was wrong.
		if (!std::equal(timestampPSKRehash.begin(),
		                timestampPSKRehash.begin() + SHA256_DIGEST_SIZE,
		                digest.begin())) {
			std::cerr << "Initialisation request had an invalid PSK hash\n";
			return std::nullopt;
		}

		std::copy_n(digest.data(), SHA256_DIGEST_SIZE,
		            packet.timestampPSKHash.begin());
	}

	std::optional<Node> referringNode{};
	{
		const auto read =
		    buffer.read(reinterpret_cast<char*>(&packet.referringNode),
		                sizeof(packet.referringNode));

		if (read != sizeof(packet.referringNode)) {
			return std::nullopt;
		}

		// Do not have details registered for referring node.
		if (referringNode = this->peers->get_peer(packet.referringNode);
		    !referringNode) {
			std::cerr << "Initialisation request originates from unknown node\n";
			return std::nullopt;
		}

		packet.referringNode =
		    Poco::ByteOrder::fromLittleEndian(packet.referringNode);
	}

	{
		std::array<char, SHA256_SIGNATURE_SIZE> signature{};
		const auto read = buffer.read(signature.data(), SHA256_SIGNATURE_SIZE);

		if (read != SHA256_SIGNATURE_SIZE) {
			return std::nullopt;
		}

		// Compare timestamp-PSK signature
		const auto timestampPSK =
		    get_bytestring(packet.timestamp) +
		    ByteString{ this->selfNode.psk.begin(), this->selfNode.psk.end() };

		const auto nodePKey = referringNode->controlPlanePublicKey;

		EVP_MD_CTX_RAII digestCtx{ EVP_MD_CTX_new() };

		if (!digestCtx) {
			return std::nullopt;
		}

		if (EVP_DigestVerifyInit(digestCtx.get(), nullptr, EVP_sha256(), nullptr,
		                         nodePKey.get()) != 1) {
			return std::nullopt;
		}

		if (EVP_DigestVerify(
		        digestCtx.get(),
		        reinterpret_cast<const std::uint8_t*>(signature.data()),
		        signature.size(),
		        reinterpret_cast<const std::uint8_t*>(timestampPSK.data()),
		        timestampPSK.size()) != 1) {
			std::cerr << "Initialisation request has invalid signature\n";
			return std::nullopt;
		}

		std::copy_n(signature.data(), SHA256_SIGNATURE_SIZE,
		            packet.timestampPSKSignature.begin());
	}

	{
		ByteString csrBytes(buffer.used(), '\0');
		buffer.read(reinterpret_cast<char*>(csrBytes.data()), csrBytes.size());

		if (auto optCSR = CertificateManager::decode_pem_csr(csrBytes)) {
			packet.csr = std::move(optCSR.value());
			const auto* subjectName = X509_REQ_get_subject_name(packet.csr.get());

			if (subjectName == nullptr) {
				return std::nullopt;
			}

			const auto commonNames = CertificateManager::get_subject_attribute(
			    subjectName, NID_commonName);

			if (commonNames.size() != 1) {
				std::cerr << "Initialisation request contains no common name\n";
				return std::nullopt;
			}

			std::clog << "Subject name: " << commonNames[0] << "\n";
		} else {
			std::cerr << "Initialisation request's CSR could not be decoded\n";
			return std::nullopt;
		}
	}

	return packet;
}

std::optional<InitialisationPacket>
PublicProtocolManager::decode_packet(ByteStringView buffer) {
	BufferType fifoBuffer{ reinterpret_cast<const char*>(buffer.data()),
		                     buffer.size() };
	fifoBuffer.setEOF(true);
	return decode_packet(fifoBuffer);
}

ByteString PublicProtocolManager::get_psk() const {
	return this->selfNode.psk;
}

std::optional<std::tuple<std::uint64_t, SHA256_Hash, SHA256_Signature>>
PublicProtocolManager::get_signed_psk() const {
	const std::uint64_t timestamp =
	    std::chrono::time_point_cast<std::chrono::seconds>(clock->now())
	        .time_since_epoch()
	        .count();
	const auto timestampPSK =
	    get_bytestring(timestamp) + get_bytestring(this->selfNode.psk);

	std::array<std::int8_t, EVP_MAX_MD_SIZE> timestampPSKBaseHash{};
	unsigned int rehashSize = 0;

	// Failed to compute SHA-256 digest
	if (EVP_Digest(timestampPSK.data(), timestampPSK.size(),
	               reinterpret_cast<std::uint8_t*>(timestampPSKBaseHash.data()),
	               &rehashSize, EVP_sha256(), nullptr) == 0 ||
	    rehashSize != SHA256_DIGEST_SIZE) {
		return std::nullopt;
	}

	SHA256_Hash sha256Hash{};
	std::copy_n(timestampPSKBaseHash.data(), SHA256_DIGEST_SIZE,
	            sha256Hash.begin());

	EVP_MD_CTX_RAII digestCtx{ EVP_MD_CTX_new() };

	if (!digestCtx) {
		return std::nullopt;
	}

	if (EVP_DigestSignInit(digestCtx.get(), nullptr, EVP_sha256(), nullptr,
	                       this->selfNode.controlPlanePrivateKey.get()) != 1) {
		return std::nullopt;
	}

	SHA256_Signature sha256Signature{};
	size_t sigLen = sha256Signature.size();

	if (EVP_DigestSign(digestCtx.get(), sha256Signature.data(), &sigLen,
	                   timestampPSK.data(), timestampPSK.size()) != 1) {
		return std::nullopt;
	};

	assert(sigLen == SHA256_SIGNATURE_SIZE);

	return std::tuple<std::uint64_t, SHA256_Hash, SHA256_Signature>{
		timestamp, sha256Hash, sha256Signature
	};
}

std::vector<Node> PublicProtocolManager::get_peer_nodes() const {
	std::vector<Node> peerNodes{};

	for (auto node : this->peers->get_peers()) {
		// Don't return the current node in list of peers.
		if (node.id == this->selfNode.id) {
			continue;
		}

		peerNodes.push_back(std::move(node));
	}

	return peerNodes;
}

const ByteString PublicProtocolManager::DEFAULT_PSK = "Testing Key"_uc;

PublicProtocolManager::PublicProtocolManager(const PublicProtocolManager& other)
    : selfNode{ other.selfNode }, clock{ other.clock }, peers{ other.peers },
      privateProtocolManager{ other.privateProtocolManager } {
	assert(this->peers);
	assert(this->selfNode.controlPlanePrivateKey);
}

std::optional<InitialisationRespPacket>
PublicProtocolManager::create_response(InitialisationPacket packet) {
	const auto allocatedNodeID = this->idDistribution(this->randomEngine);
	// Non-owning ptr to the request's subject name.
	X509_NAME* subjectName = X509_REQ_get_subject_name(packet.csr.get());

	// Set the serial-number attribute to be node's ID.
	GenericCertificateManager<char>::set_subject_attribute(
	    subjectName, NID_serialNumber, std::to_string(allocatedNodeID));

	const auto signedCSR = CertificateManager::sign_csr(
	    packet.csr, this->selfNode.controlPlaneCertificate,
	    this->selfNode.controlPlanePrivateKey,
	    PublicProtocolManager::DEFAULT_CERTIFICATE_VALIDITY_SECONDS);

	if (!signedCSR) {
		return std::nullopt;
	}

	auto certificateChain = peers->get_certificate_chain(this->selfNode.id);

	// Peer will not accept response without certificate chain, so fail.
	if (!certificateChain.has_value()) {
		return std::nullopt;
	}

	certificateChain->push_back(signedCSR.value());

	// TODO: Complete.
	return InitialisationRespPacket{
		.respondingNode = this->selfNode.id,
		.allocatedNode = allocatedNodeID,
		.respondingWireGuardPublicKey = this->selfNode.wireGuardPublicKey,
		.respondingControlPlaneIPAddress = this->selfNode.controlPlaneIP,
		.respondingWireGuardIPAddress =
		    this->selfNode.connectionDetails->wireGuardHost,
		.respondingControlPlanePort =
		    this->selfNode.connectionDetails->controlPlanePort,
		.respondingWireGuardPort = this->selfNode.connectionDetails->wireGuardPort,
		.certificateChain = certificateChain.value(),
	};
}

PublicProtocolManager::ConnectionFactory::ConnectionFactory(
    PublicProtocolManager& parent)
    : parent{ parent } {}

Poco::Net::TCPServerConnection*
PublicProtocolManager::ConnectionFactory::createConnection(
    const Poco::Net::StreamSocket& socket) {
	return new PublicConnection{ socket, parent };
}

// TODO: Investigate whether SO_LINGER should be disabled.
PublicConnection::PublicConnection(const Poco::Net::StreamSocket& socket,
                                   PublicProtocolManager& parent)
    : Poco::Net::TCPServerConnection{ socket }, parent{ parent } {
	this->socket().setReceiveBufferSize(InitialisationPacket::MAX_PACKET_SIZE);
}

void PublicConnection::run() {
	BufferType buffer{ InitialisationPacket::MAX_PACKET_SIZE };

	if (socket().receiveBytes(buffer) < InitialisationPacket::MIN_PACKET_SIZE) {
		return;
	}

	if (auto packet = parent.decode_packet(buffer)) {
		const auto responsePacket =
		    parent.create_response(std::move(packet.value()));

		assert(!responsePacket->certificateChain.empty());
		const auto peerCertificate = responsePacket->certificateChain.back();
		assert(peerCertificate != nullptr);

		// TODO: Discover peer WG pubkey from certificate.
		auto* const subjectName = X509_get_subject_name(peerCertificate.get());
		const auto subjectUserIDB64 =
		    CertificateManager::get_subject_attribute(subjectName, NID_userId);

		// If the isn't a single subject UserID.
		if (subjectUserIDB64.size() != 1) {
			std::cerr << "Peer did not specify a single WireGuard public key\n";
			return;
		}

		const auto subjectUserID = base64_decode(subjectUserIDB64[0]);

		if (!subjectUserID ||
		    subjectUserID->size() != AbstractWireGuardManager::WG_KEY_SIZE) {
			std::cerr << "Peer specified an invalid base-64 user ID\n";
			return;
		}

		const auto certificatePubkey =
		    CertificateManager::get_certificate_pubkey(peerCertificate);

		if (!certificatePubkey) {
			std::cerr << "Failed to decode peer certificate's public key\n";
			return;
		}

		AbstractWireGuardManager::Key peerWGPubkey = {};
		std::copy(subjectUserID.value().begin(), subjectUserID.value().end(),
		          peerWGPubkey.begin());

		// TODO: Don't just rely on the default WireGuard port, or potentially mark
		// connection details as unknown.
		const auto peer = Node{
			.id = responsePacket->allocatedNode,
			.controlPlanePublicKey = certificatePubkey.value(),
			.wireGuardPublicKey = peerWGPubkey,
			.controlPlaneIP =
			    Node::get_control_plane_ip(responsePacket->allocatedNode),
			.connectionDetails =
			    NodeConnection{
			        .controlPlanePort = 0,
			        .wireGuardHost = Host{ socket().peerAddress().host() },
			        .wireGuardPort = Node::DEFAULT_WIREGUARD_PORT,
			    },
			.controlPlaneCertificate = peerCertificate,
			.parent = packet->referringNode,
		};
		// If this is a newly added peer.
		if (parent.peers->add_peer(peer)) {
			parent.privateProtocolManager.accept_peer_request(parent.selfNode.id,
			                                                  peer);
		}

		if (responsePacket) {
			const auto responsePacketBytes = responsePacket->get_bytes();
			assert(responsePacketBytes.size() < std::numeric_limits<int>::max());

			if (socket().sendBytes(responsePacketBytes.data(),
			                       static_cast<int>(responsePacketBytes.size())) <
			    0) {
				std::cerr << "Failed to send response to peer: " << strerror(errno)
				          << "\n";
			}
		}
	} else {
		std::clog << "Invalid connection request from: "
		          << socket().peerAddress().host().toString() << "\n";
	}
}

[[nodiscard]] ByteString InitialisationPacket::get_bytes() const {
	return get_bytestring(timestamp, timestampPSKHash, referringNode,
	                      timestampPSKSignature,
	                      CertificateManager::encode_pem(csr));
}

std::strong_ordering
InitialisationPacket::operator<=>(const InitialisationPacket& other) const {
	const auto nonCert =
	    std::tie(this->timestamp, this->referringNode,
	             this->timestampPSKSignature, this->timestampPSKHash) <=>
	    std::tie(other.timestamp, other.referringNode,
	             other.timestampPSKSignature, other.timestampPSKHash);

	if (nonCert != std::strong_ordering::equal) {
		return nonCert;
	}

	unsigned char* thisCSR = nullptr;
	const auto thisCSRSize = i2d_X509_REQ(this->csr.get(), &thisCSR);
	OPENSSL_RAII<unsigned char> thisCSRRAII{ thisCSR };
	if (thisCSRSize < 0) {
		// If encoding this packet's CSR to DER failed, just return equality.
		return std::strong_ordering::equal;
	}

	unsigned char* otherCSR = nullptr;
	const auto otherCSRSize = i2d_X509_REQ(other.csr.get(), &otherCSR);
	OPENSSL_RAII<unsigned char> otherCSRRAII{ otherCSR };
	if (otherCSRSize < 0) {
		// If encoding other packet's CSR to DER failed, just return equality.
		return std::strong_ordering::equal;
	}

	if (thisCSRSize != otherCSRSize) {
		return thisCSRSize <=> otherCSRSize;
	}

	return compare(thisCSRRAII.get(), thisCSRRAII.get() + thisCSRSize,
	               otherCSRRAII.get());
}

bool InitialisationPacket::operator==(const InitialisationPacket& other) const {
	return (*this <=> other) == std::strong_ordering::equal;
}

ByteString InitialisationRespPacket::get_bytes() const {
	return get_bytestring(
	    this->respondingNode, this->allocatedNode,
	    this->respondingWireGuardPublicKey, this->respondingControlPlaneIPAddress,
	    this->respondingWireGuardIPAddress, this->respondingControlPlanePort,
	    this->respondingWireGuardPort,
	    CertificateManager::encode_pem(this->certificateChain));
}

std::optional<InitialisationRespPacket>
InitialisationRespPacket::decode_bytes(const ByteString& bytes) {
	if (bytes.size() < InitialisationRespPacket::MIN_PACKET_SIZE ||
	    bytes.size() > InitialisationRespPacket::MAX_PACKET_SIZE) {
		return std::nullopt;
	}

	InitialisationRespPacket packet{};
	auto position = bytes.begin();

	const auto read =
	    [&position, bytesEnd = bytes.end()](
	        std::iterator_traits<ByteString::iterator>::difference_type byteCount)
	    -> std::optional<ByteStringView> {
		if (std::distance(position, bytesEnd) < byteCount) {
			return std::nullopt;
		}

		const auto prevPosition = position;
		position += byteCount;
		return ByteStringView{ prevPosition, position };
	};

	{
		const auto respondingNodeBytes = read(sizeof(packet.respondingNode));

		if (!respondingNodeBytes) {
			return std::nullopt;
		}

		std::copy(respondingNodeBytes->begin(), respondingNodeBytes->end(),
		          reinterpret_cast<std::uint8_t*>(&packet.respondingNode));

		packet.respondingNode =
		    Poco::ByteOrder::fromLittleEndian(packet.respondingNode);
	}

	{
		const auto allocatedNodeBytes = read(sizeof(packet.allocatedNode));

		if (!allocatedNodeBytes) {
			return std::nullopt;
		}

		std::copy(allocatedNodeBytes->begin(), allocatedNodeBytes->end(),
		          reinterpret_cast<std::uint8_t*>(&packet.allocatedNode));
		packet.allocatedNode =
		    Poco::ByteOrder::fromLittleEndian(packet.allocatedNode);
	}

	{
		const auto respondingWireGuardPublicKeyBytes =
		    read(AbstractWireGuardManager::WG_KEY_SIZE);

		if (!respondingWireGuardPublicKeyBytes) {
			return std::nullopt;
		}

		std::copy(respondingWireGuardPublicKeyBytes->begin(),
		          respondingWireGuardPublicKeyBytes->end(),
		          packet.respondingWireGuardPublicKey.begin());
	}

	{
		const auto respondingControlPlaneIPAddressBytes = read(IPV6_ADDR_SIZE);

		if (!respondingControlPlaneIPAddressBytes) {
			return std::nullopt;
		}

		in6_addr addr{};
		std::copy(respondingControlPlaneIPAddressBytes->begin(),
		          respondingControlPlaneIPAddressBytes->end(), addr.s6_addr);

		packet.respondingControlPlaneIPAddress =
		    decode_ip_address(Poco::Net::IPAddress{ &addr, sizeof(addr) });
	}

	{
		const auto respondingWireGuardIPAddressBytes = read(IPV6_ADDR_SIZE);

		if (!respondingWireGuardIPAddressBytes) {
			return std::nullopt;
		}

		in6_addr addr{};
		std::copy(respondingWireGuardIPAddressBytes->begin(),
		          respondingWireGuardIPAddressBytes->end(), addr.s6_addr);

		packet.respondingWireGuardIPAddress =
		    decode_ip_address(Poco::Net::IPAddress{ &addr, sizeof(addr) });
	}

	{
		const auto respondingControlPlanePortBytes =
		    read(sizeof(packet.respondingControlPlanePort));

		if (!respondingControlPlanePortBytes) {
			return std::nullopt;
		}

		std::copy(
		    respondingControlPlanePortBytes->begin(),
		    respondingControlPlanePortBytes->end(),
		    reinterpret_cast<std::uint8_t*>(&packet.respondingControlPlanePort));
		packet.respondingControlPlanePort =
		    Poco::ByteOrder::fromLittleEndian(packet.respondingControlPlanePort);
	}

	{
		const auto respondingWireGuardPortBytes =
		    read(sizeof(packet.respondingWireGuardPort));

		if (!respondingWireGuardPortBytes) {
			return std::nullopt;
		}

		std::copy(respondingWireGuardPortBytes->begin(),
		          respondingWireGuardPortBytes->end(),
		          reinterpret_cast<std::uint8_t*>(&packet.respondingWireGuardPort));
		packet.respondingWireGuardPort =
		    Poco::ByteOrder::fromLittleEndian(packet.respondingWireGuardPort);
	}

	{
		ByteStringView certificateChainBytes{ position, bytes.end() };

		if (auto optCertificateChain =
		        CertificateManager::decode_pem_certificate_chain(
		            certificateChainBytes)) {
			packet.certificateChain = std::move(optCertificateChain.value());
		} else {
			return std::nullopt;
		}
	}

	return packet;
}

PublicProtocolClient::PublicProtocolClient(Configuration config)
    : config{ std::move(config) } {}

InitialisationRespPacket PublicProtocolClient::connect() {
	const std::optional<std::uint16_t> port = config.parentAddress.port();

	const Poco::Net::IPAddress parentAddress = [](const Host& parentAddress) {
		try {
			return static_cast<Poco::Net::IPAddress>(parentAddress);
		} catch (const Poco::RuntimeException& e) {
			throw std::invalid_argument{ "Couldn't understand parent address '" +
				                           static_cast<std::string>(parentAddress) +
				                           "': " + e.what() };
		}
	}(config.parentAddress);

	auto csr = CertificateManager::generate_certificate_request(config.certInfo);

	if (!csr) {
		throw std::runtime_error{ "Couldn't generate certificate signing request" };
	}

	// Create initialisation packet before connecting to avoid delays actually
	// sending the data.
	const PublicProtocol::InitialisationPacket initPacket{
		.timestamp = config.timestamp,
		.timestampPSKHash = config.pskHash,
		.referringNode = config.referringNode,
		.timestampPSKSignature = config.pskSignature,
		.csr = std::move(csr.value()),
	};

	Poco::Net::StreamSocket publicSocket{ Poco::Net::SocketAddress(
		  { parentAddress,
		    port.value_or(PublicProtocol::DEFAULT_CONTROL_PLANE_PORT) }) };

	const auto bytes = initPacket.get_bytes();

	assert(bytes.size() < std::numeric_limits<int>::max());
	publicSocket.sendBytes(bytes.data(), static_cast<int>(bytes.size()));
	ByteString responseBytes(
	    PublicProtocol::InitialisationRespPacket::MAX_PACKET_SIZE, '\0');

	assert(responseBytes.size() < std::numeric_limits<int>::max());

	if (publicSocket.receiveBytes(responseBytes.data(),
	                              static_cast<int>(responseBytes.size())) <
	    PublicProtocol::InitialisationRespPacket::MIN_PACKET_SIZE) {
		throw std::runtime_error{
			"Failed to receive a valid response from the parent server"
		};
	}

	auto response =
	    PublicProtocol::InitialisationRespPacket::decode_bytes(responseBytes);

	if (!response) {
		throw std::runtime_error{
			"Response received from the parent server was invalid"
		};
	}

	// If parent is listening on all IPs (i.e. a global address of ::/0 or
	// 0.0.0.0/0), then use the address we used to connect to them instead.
	if (response->respondingWireGuardIPAddress.prefixLength() == 0) {
		response->respondingWireGuardIPAddress = parentAddress;
	}

	std::cerr << "Received response from parent server ("
	          << response->respondingNode << "), allocated node "
	          << response->allocatedNode << ".\n"
	          << "Parent's dataplane IP is "
	          << response->respondingWireGuardIPAddress.toString() << ":"
	          << response->respondingWireGuardPort << "\n";

	return response.value();

	// TODO: Use HTTPS / DNS to verify response.
}

Host PublicProtocolClient::get_parent_address(
    const InitialisationRespPacket& response) const {
	if (config.parentAddress) {
		return config.parentAddress;
	}

	return Host{ response.respondingWireGuardIPAddress };
}
