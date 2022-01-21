#include "public-protocol.hpp"
#include <Poco/ByteOrder.h>
#include <cassert>
#include <iostream>
#include <limits>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <utility>

using namespace PublicProtocol;

template <std::integral IntType>
constexpr IntType base64_decoded_character_count(const IntType bytes) noexcept {
	const constexpr IntType b64GroupAlignment = 3;
	const constexpr IntType b64GroupSize = 4;
	assert(bytes % b64GroupSize == 0);

	return (bytes / b64GroupSize) * b64GroupAlignment;
}

PublicProtocolManager::PublicProtocolManager(std::string psk, const Node& self)
    : psk{ std::move(psk) } {
	this->nodes.insert(std::make_pair(self.id, self));
}

void PublicProtocolManager::start(const Poco::Net::ServerSocket& serverSocket,
                                  Poco::Net::TCPServerParams::Ptr params) {
	Poco::Net::TCPServer server{ new ConnectionFactory(*this), serverSocket,
		                           std::move(params) };
	server.start();
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
		const auto leTimestamp = Poco::ByteOrder::toLittleEndian(packet.timestamp);
		const std::string timestampPSK =
		    PublicProtocolManager::byte_string(leTimestamp) + this->psk;
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
		const auto leTimestamp = Poco::ByteOrder::toLittleEndian(packet.timestamp);
		const std::string timestampPSK =
		    PublicProtocolManager::byte_string(leTimestamp) + this->psk;

		const auto nodePKey = get_node_pkey(*referringNode);
		std::string typeName = EVP_PKEY_get0_type_name(nodePKey->get());
		std::cout << typeName << "\n";
		std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)> digestCtx{
			EVP_MD_CTX_new(), &::EVP_MD_CTX_free
		};

		if (!digestCtx) {
			return std::nullopt;
		}

		if (EVP_DigestVerifyInit(digestCtx.get(), nullptr, EVP_sha256(), nullptr,
		                         nodePKey->get()) != 1) {
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

	packet.csr.resize(buffer.used());
	buffer.read(packet.csr.data(), packet.csr.size());

	return packet;
}

std::optional<InitialisationPacket>
PublicProtocolManager::decode_packet(std::span<const char> buffer) {
	BufferType fifoBuffer{ buffer.data(), buffer.size() };
	fifoBuffer.setEOF(true);
	return decode_packet(fifoBuffer);
}

template <std::integral Integral>
std::string PublicProtocolManager::byte_string(Integral value) {
	union {
		Integral baseType;
		char bytes[sizeof(Integral)]; // NOLINT(modernize-avoid-c-arrays)
	} aliasing = {
		.baseType = value,
	};

	return std::string{ aliasing.bytes, aliasing.bytes + sizeof(Integral) };
}

std::optional<std::vector<std::uint8_t>>
PublicProtocolManager::base64_decode(std::span<char> bytes) {
	assert(bytes.size() < std::numeric_limits<int>::max());
	assert(!bytes.empty());

	const std::integral auto expectedDecodedByteCount =
	    base64_decoded_character_count(bytes.size());
	std::vector<std::uint8_t> decoded(expectedDecodedByteCount, '\0');
	const decltype(expectedDecodedByteCount) decodedByteCount = EVP_DecodeBlock(
	    reinterpret_cast<unsigned char*>(decoded.data()),
	    reinterpret_cast<unsigned char*>(bytes.data()), bytes.size());

	if (decodedByteCount != expectedDecodedByteCount) {
		return std::nullopt;
	}

	return decoded;
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
    : psk{ other.psk } {
	std::scoped_lock nodesLock{ other.nodesMutex, this->nodesMutex };
	this->nodes = other.nodes;
}

std::optional<EVP_PKEY_RAII>
PublicProtocolManager::get_node_pkey(const Node& node) {
	const auto* data = reinterpret_cast<const uint8_t*>(node.publicKey.data());

	std::unique_ptr<BIO, decltype(&::BIO_free)> dataBuf{
		BIO_new_mem_buf(data, node.publicKey.size()), &::BIO_free
	};
	EVP_PKEY* tmpPKey =
	    PEM_read_bio_PUBKEY(dataBuf.get(), nullptr, nullptr, nullptr);

	if (!tmpPKey) {
		return std::nullopt;
	}

	return EVP_PKEY_RAII{ tmpPKey, &::EVP_PKEY_free };
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
	this->socket().setReceiveBufferSize(
	    PublicProtocolManager::INIT_PACKET_BUFFER_SIZE);
}

void PublicConnection::run() {
	std::cout << "New connection from: "
	          << socket().peerAddress().host().toString() << "\n";
	BufferType buffer{ PublicProtocolManager::INIT_PACKET_BUFFER_SIZE };

	if (socket().receiveBytes(buffer) <
	    PublicProtocolManager::MIN_PACKET_BUFFER_SIZE) {
		return;
	}

	if (const auto packet = parent.decode_packet(buffer)) {
		// TODO: Respond with necessary data.
	}
}
