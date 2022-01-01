#include "public-protocol.hpp"
#include <Poco/ByteOrder.h>
#include <cassert>
#include <iostream>
#include <limits>
#include <openssl/evp.h>
#include <utility>

PublicProtocolManager::PublicProtocolManager(
    const Poco::Net::ServerSocket& serverSocket,
    Poco::Net::TCPServerParams::Ptr params)
    : server{
	      new Poco::Net::TCPServerConnectionFactoryImpl<ConnectionHandler>(),
	      serverSocket, std::move(params)
      } {}

void PublicProtocolManager::start() {
	server.start();
}

// TODO: Investigate whether SO_LINGER should be disabled.
ConnectionHandler::ConnectionHandler(const Poco::Net::StreamSocket& socket)
    : Poco::Net::TCPServerConnection{ socket } {
	this->socket().setReceiveBufferSize(INIT_PACKET_BUFFER_SIZE);
}

void ConnectionHandler::run() {
	std::cout << "New connection from: "
	          << socket().peerAddress().host().toString() << "\n";
	BufferType buffer{ INIT_PACKET_BUFFER_SIZE };

	if (socket().receiveBytes(buffer) < MIN_PACKET_BUFFER_SIZE) {
		return;
	}

	if (const auto packet = decode_packet(buffer)) {
		// TODO: Respond with necessary data.
	}
}

std::optional<InitialisationPacket>
ConnectionHandler::decode_packet(BufferType& buffer) {
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
		char digest[SHA256_DIGEST_SIZE] = { 0 };
		const auto read = buffer.read(digest, SHA256_DIGEST_SIZE);

		if (read != SHA256_DIGEST_SIZE) {
			return std::nullopt;
		}

		std::copy_n(digest, SHA256_DIGEST_SIZE, packet.timestampPSKHash.begin());
	}

	{
		const auto read =
		    buffer.read(reinterpret_cast<char*>(&packet.referringNode),
		                sizeof(packet.referringNode));

		if (read != sizeof(packet.referringNode)) {
			return std::nullopt;
		}

		packet.referringNode =
		    Poco::ByteOrder::fromLittleEndian(packet.referringNode);
	}

	{
		char signature[SHA256_SIGNATURE_SIZE] = { 0 };
		const auto read = buffer.read(signature, SHA256_SIGNATURE_SIZE);

		if (read != SHA256_SIGNATURE_SIZE) {
			return std::nullopt;
		}

		std::copy_n(signature, SHA256_SIGNATURE_SIZE,
		            packet.timestampPSKSignature.begin());
	}

	packet.csr.resize(buffer.used());
	buffer.read(packet.csr.data(), packet.csr.size());

	return packet;
}

template <std::integral IntType>
constexpr IntType base64_decoded_character_count(const IntType bytes) noexcept {
	const constexpr IntType b64GroupAlignment = 3;
	const constexpr IntType b64GroupSize = 4;
	assert(bytes % b64GroupSize == 0);

	return (bytes / b64GroupSize) * b64GroupAlignment;
}

std::optional<std::vector<std::uint8_t>>
ConnectionHandler::base64_decode(std::span<char> bytes) {
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

std::optional<InitialisationPacket>
ConnectionHandler::decode_packet(const std::span<const char> buffer) {
	BufferType fifoBuffer{ buffer.data(), buffer.size() };
	fifoBuffer.setEOF(true);
	return decode_packet(fifoBuffer);
}
