#pragma once
#include <Poco/Net/TCPServer.h>
#include <concepts>
#include <optional>
#include <span>

const constexpr std::uint16_t SHA256_DIGEST_SIZE = 32;
const constexpr std::uint16_t SHA256_SIGNATURE_SIZE = 256;

template <std::integral IntType>
constexpr IntType base64_encoded_character_count(IntType bytes) noexcept {
	const constexpr IntType b64GroupAlignment = 3;
	const constexpr IntType b64GroupSize = 4;

	// Round up to nearest B64_ALIGNMENT bytes
	const IntType b64Groups = (bytes + b64GroupAlignment - 1) / b64GroupAlignment;

	return b64GroupSize * b64Groups;
}

/**
 * Initialisation packet. The first packet sent by a potential client to a node
 * capable of authorising connections.
 */
struct InitialisationPacket {
	using Hash = std::array<std::uint8_t, SHA256_DIGEST_SIZE>;
	using Signature = std::array<std::uint8_t, SHA256_SIGNATURE_SIZE>;

	std::uint64_t timestamp;
	Hash timestampPSKHash;
	std::uint64_t referringNode;
	Signature timestampPSKSignature;
	std::string csr;

	bool operator<=>(const InitialisationPacket& other) const = default;
};

class PublicProtocolManager {
public:
	PublicProtocolManager(const Poco::Net::ServerSocket& serverSocket,
	                      Poco::Net::TCPServerParams::Ptr params, std::string psk);
	virtual ~PublicProtocolManager() = default;

	void start();

protected:
	Poco::Net::TCPServer server;
	std::string psk;
};

class ConnectionHandler : public Poco::Net::TCPServerConnection {
public:
	ConnectionHandler(const Poco::Net::StreamSocket& socket);
	~ConnectionHandler() override = default;
	void run() override;

	static std::optional<InitialisationPacket>
	decode_packet(std::span<const char> buffer, const std::string& psk);

protected:
	std::string psk;

	using BufferType = Poco::FIFOBuffer;
	static std::optional<InitialisationPacket> decode_packet(BufferType& buffer,
	                                                         const std::string& psk);

	static std::optional<std::vector<std::uint8_t>>
	base64_decode(std::span<char> bytes);

	template <std::integral Integral>
	static std::string byte_string(Integral value);

	static const constexpr std::uint16_t SHA256_DIGEST_B64_SIZE =
	    base64_encoded_character_count(SHA256_DIGEST_SIZE);
	static const constexpr std::uint16_t SHA256_SIGNATURE_B64_SIZE =
	    base64_encoded_character_count(SHA256_SIGNATURE_SIZE);
	static const constexpr std::uint16_t MIN_PACKET_BUFFER_SIZE =
	    sizeof(InitialisationPacket::timestamp) + SHA256_DIGEST_B64_SIZE +
	    sizeof(InitialisationPacket::referringNode) + SHA256_SIGNATURE_B64_SIZE;
	static const constexpr std::uint16_t MAX_CSR_SIZE = 1200;
	// Size: MIN_PACKET_BUFFER_SIZE + sizeof(csr) ~= 1675 bytes.
	static const constexpr std::uint16_t INIT_PACKET_BUFFER_SIZE =
	    MIN_PACKET_BUFFER_SIZE + MAX_CSR_SIZE;
};
