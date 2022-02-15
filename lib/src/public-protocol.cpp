#include "public-protocol.hpp"
#include "certificates.hpp"
#include "utilities.hpp"
#include <Poco/ByteOrder.h>
#include <Poco/Net/TCPServer.h>
#include <cassert>
#include <ios>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <utility>

using namespace PublicProtocol;

PublicProtocolManager::PublicProtocolManager(
    std::string psk, Node self, EVP_PKEY_RAII controlPlanePrivateKey)
    : psk{ std::move(psk) }, selfNode{ self },
      controlPlanePrivateKey{ std::move(controlPlanePrivateKey) } {
	this->nodes.insert(std::make_pair(self.id, std::move(self)));
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
	}

	{
		std::array<char, SHA256_DIGEST_SIZE> digest{};
		const auto read = buffer.read(digest.data(), SHA256_DIGEST_SIZE);

		if (read != SHA256_DIGEST_SIZE) {
			return std::nullopt;
		}

		// Re-compute timestamp-PSK hash and compare
		const auto timestampPSK = get_bytestring(packet.timestamp) +
		                          ByteString{ this->psk.begin(), this->psk.end() };
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
		if (referringNode = this->get_node(packet.referringNode); !referringNode) {
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
		const auto timestampPSK = get_bytestring(packet.timestamp) +
		                          ByteString{ this->psk.begin(), this->psk.end() };

		const auto optNodePKey = get_node_pkey(referringNode.value());

		if (!optNodePKey) {
			return std::nullopt;
		}

		const auto& nodePKey = optNodePKey.value();
		std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)> digestCtx{
			EVP_MD_CTX_new(), &::EVP_MD_CTX_free
		};

		if (!digestCtx) {
			return std::nullopt;
		}

		if (EVP_DigestVerifyInit(digestCtx.get(), nullptr, EVP_sha256(), nullptr,
		                         nodePKey.get()) != 1) {
			return std::nullopt;
		}

		const int verified = EVP_DigestVerify(
		    digestCtx.get(),
		    reinterpret_cast<const std::uint8_t*>(signature.data()),
		    signature.size(),
		    reinterpret_cast<const std::uint8_t*>(timestampPSK.data()),
		    timestampPSK.size());

		if (verified != 1) {
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
				return std::nullopt;
			}

			std::clog << "Subject name: " << commonNames[0] << "\n";
		} else {
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

bool PublicProtocolManager::add_node(const Node& node) {
	std::lock_guard<std::mutex> nodesLock{ nodesMutex };
	return this->nodes.insert(std::make_pair(node.id, node)).second;
}

std::optional<Node>
PublicProtocolManager::get_node(std::uint64_t nodeID) const {
	std::lock_guard<std::mutex> nodesLock{ nodesMutex };
	const auto value = this->nodes.find(nodeID);

	if (value == this->nodes.end()) {
		return std::nullopt;
	}

	return value->second;
}

bool PublicProtocolManager::delete_node(const Node& node) {
	std::lock_guard<std::mutex> nodesLock{ nodesMutex };
	return this->nodes.erase(node.id) == 1;
}

PublicProtocolManager::PublicProtocolManager(const PublicProtocolManager& other)
    : psk{ other.psk }, selfNode{ other.selfNode }, controlPlanePrivateKey{
	      EVP_PKEY_dup(other.controlPlanePrivateKey.get())
      } {
	std::scoped_lock nodesLock{ other.nodesMutex, this->nodesMutex };
	this->nodes = other.nodes;
}

std::optional<EVP_PKEY_RAII>
PublicProtocolManager::get_node_pkey(const Node& node) {
	assert(node.controlPlanePublicKey.size() < std::numeric_limits<int>::max());
	const auto* data =
	    reinterpret_cast<const uint8_t*>(node.controlPlanePublicKey.data());

	std::unique_ptr<BIO, decltype(&::BIO_free)> dataBuf{
		BIO_new_mem_buf(data, static_cast<int>(node.controlPlanePublicKey.size())),
		&::BIO_free
	};
	EVP_PKEY* tmpPKey =
	    PEM_read_bio_PUBKEY(dataBuf.get(), nullptr, nullptr, nullptr);

	if (tmpPKey == nullptr) {
		return std::nullopt;
	}

	return EVP_PKEY_RAII{ tmpPKey };
}

std::optional<InitialisationRespPacket>
PublicProtocolManager::create_response(InitialisationPacket packet) {
	const auto signedCSR = CertificateManager::sign_csr(
	    packet.csr, this->selfNode.controlPlaneCertificate,
	    this->controlPlanePrivateKey,
	    PublicProtocolManager::DEFAULT_CERTIFICATE_VALIDITY_SECONDS);

	if (!signedCSR) {
		return std::nullopt;
	}

	// TODO: Complete.
	return InitialisationRespPacket{
		.respondingNode = this->selfNode.id,
		.allocatedNode = /* TODO: Generate a node ID */ 0,
		.respondingWireGuardPublicKey = this->selfNode.wireGuardPublicKey,
		.respondingControlPlaneIPAddress = this->selfNode.controlPlaneIP,
		.respondingWireGuardIPAddress = this->selfNode.wireGuardIP,
		.respondingControlPlanePort = this->selfNode.controlPlanePort,
		.respondingWireGuardPort = this->selfNode.wireGuardPort,
		.signedCSR = signedCSR.value(),
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
	const auto respondingNodeLE =
	    Poco::ByteOrder::fromLittleEndian(this->respondingNode);
	const auto allocatedNodeLE =
	    Poco::ByteOrder::fromLittleEndian(this->allocatedNode);
	const auto respondingControlPlanePortLE =
	    Poco::ByteOrder::fromLittleEndian(this->respondingControlPlanePort);
	const auto respondingWireguardPortLE =
	    Poco::ByteOrder::fromLittleEndian(this->respondingWireGuardPort);

	ByteString bytes = get_bytestring(
	    respondingNodeLE, allocatedNodeLE, this->respondingWireGuardPublicKey,
	    this->respondingControlPlaneIPAddress, this->respondingWireGuardIPAddress,
	    respondingControlPlanePortLE, respondingWireguardPortLE,
	    CertificateManager::encode_pem(this->signedCSR));

	return bytes;
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
		const auto respondingWireGuardPublicKeyBytes = read(Node::WG_PUBKEY_SIZE);

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
		    Poco::Net::IPAddress{ &addr, sizeof(addr) };
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
		    Poco::Net::IPAddress{ &addr, sizeof(addr) };
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
		ByteStringView signedCSRBytes{ position, bytes.end() };

		if (auto optSignedCSR =
		        CertificateManager::decode_pem_certificate(signedCSRBytes)) {
			packet.signedCSR = std::move(optSignedCSR.value());
		} else {
			return std::nullopt;
		}
	}

	return packet;
}
