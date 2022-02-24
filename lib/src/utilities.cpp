#include "utilities.hpp"
#include <bit>
#include <cassert>
#include <openssl/hmac.h>
#include <span>

const constexpr std::uint32_t IPV6_ADDR_LENGTH = 16;

ByteString get_bytestring(Poco::Net::IPAddress address) {
	assert(address.family() == Poco::Net::AddressFamily::IPv4 ||
	       address.family() == Poco::Net::AddressFamily::IPv6);

	if (address.family() == Poco::Net::AddressFamily::IPv4) {
		address = Poco::Net::IPAddress::parse("::ffff:" + address.toString());
		assert(address.family() == Poco::Net::AddressFamily::IPv6);
	}

	assert(address.af() == AF_INET6);

	const std::span addressBytes = {
		static_cast<const in6_addr*>(address.addr())->s6_addr, IPV6_ADDR_LENGTH
	};
	ByteString littleEndianBytes{};

	if (std::endian::native == std::endian::big) {
		littleEndianBytes =
		    ByteString{ addressBytes.rbegin(), addressBytes.rend() };
	} else {
		littleEndianBytes = ByteString{ addressBytes.begin(), addressBytes.end() };
	}

	assert(littleEndianBytes.size() == IPV6_ADDR_LENGTH);
	return littleEndianBytes;
}

ByteString get_bytestring(const std::string& string) {
	return ByteString{ string.begin(), string.end() };
}

ByteString get_bytestring(const ByteString& string) {
	return string;
}

std::optional<ByteString> base64_decode(std::string_view bytes) {
	return base64_decode(std::span<const std::uint8_t>{
	    reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size() });
}

std::optional<ByteString>
base64_decode(const std::span<const std::uint8_t> bytes) {
	assert(bytes.size() < std::numeric_limits<int>::max());

	if (bytes.empty()) {
		return ByteString{};
	}

	for (const auto byte : bytes) {
		if (!is_valid_base64_digit(byte)) {
			return std::nullopt;
		}
	}

	const auto expectedDecodedByteCount =
	    base64_decoded_character_count(bytes.size());

	if (!expectedDecodedByteCount.has_value()) {
		return std::nullopt;
	}

	ByteString decoded(expectedDecodedByteCount.value(), '\0');
	int decodedByteCount = EVP_DecodeBlock(decoded.data(), bytes.data(),
	                                       static_cast<int>(bytes.size()));

	if (decodedByteCount < 0 ||
	    expectedDecodedByteCount !=
	        static_cast<std::uint32_t>(decodedByteCount)) {
		return std::nullopt;
	}

	// Handle padding, since OpenSSL doesn't do that for us.
	for (std::uint8_t i = 1; i <= 2; i++) {
		if (bytes[bytes.size() - i] == '=' && decodedByteCount > 0) {
			decodedByteCount--;
		}
	}

	decoded.resize(decodedByteCount);

	return decoded;
}

std::optional<std::string> base64_encode(ByteString bytes) {
	return base64_encode(
	    std::span<const std::uint8_t>{ bytes.data(), bytes.size() });
}

std::optional<std::string> base64_encode(std::span<const std::uint8_t> bytes) {
	assert(bytes.size() < std::numeric_limits<int>::max());
	const auto expectedEncodedSize = base64_encoded_character_count(bytes.size());
	std::string encoded(expectedEncodedSize, '\0');
	const auto encodedSize =
	    EVP_EncodeBlock(reinterpret_cast<std::uint8_t*>(encoded.data()),
	                    bytes.data(), static_cast<int>(bytes.size()));
	if (encodedSize == -1) {
		return std::nullopt;
	};

	encoded.resize(encodedSize);

	return encoded;
}

std::optional<std::uint64_t>
base64_decoded_character_count(const std::uint64_t bytes) noexcept {
	const constexpr std::uint64_t b64GroupAlignment = 3;
	const constexpr std::uint64_t b64GroupSize = 4;

	if (bytes % b64GroupSize != 0) {
		return std::nullopt;
	}

	return (bytes / b64GroupSize) * b64GroupAlignment;
}

template <typename StrType>
StrType trim(const auto* begin, const auto* end) {
	while (begin != end && isspace(*begin) != 0) {
		begin++;
	}

	while (begin != end && isspace(*(end - 1)) != 0) {
		end--;
	}

	return StrType{ begin, end };
}

std::string trim(const std::string_view& string) {
	return trim<std::string>(string.begin(), string.end());
}

ByteString trim(const ByteStringView& string) {
	return trim<ByteString>(string.begin(), string.end());
}

bool is_valid_base64_digit(std::uint8_t byte) {
	return (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
	       (byte >= 'a' && byte <= 'z') || byte == '+' || byte == '/' ||
	       byte == '=';
}
