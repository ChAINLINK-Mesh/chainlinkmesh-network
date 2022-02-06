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

std::optional<ByteString> base64_decode(std::string_view bytes) {
	return base64_decode(std::span<const std::uint8_t>{
	    reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size() });
}

std::optional<ByteString> base64_decode(const std::span<const std::uint8_t> bytes) {
	assert(bytes.size() < std::numeric_limits<int>::max());
	assert(!bytes.empty());

	const std::integral auto expectedDecodedByteCount =
	    base64_decoded_character_count(bytes.size());
	ByteString decoded(expectedDecodedByteCount, '\0');
	const decltype(expectedDecodedByteCount) decodedByteCount = EVP_DecodeBlock(
	    decoded.data(), bytes.data(), static_cast<int>(bytes.size()));

	if (decodedByteCount != expectedDecodedByteCount) {
		return std::nullopt;
	}

	return decoded;
}

template <std::integral IntType>
constexpr IntType base64_decoded_character_count(const IntType bytes) noexcept {
	const constexpr IntType b64GroupAlignment = 3;
	const constexpr IntType b64GroupSize = 4;
	assert(bytes % b64GroupSize == 0);

	return (bytes / b64GroupSize) * b64GroupAlignment;
}

std::string trim(const std::string& string) {
	auto begin = string.begin();
	auto end = string.end();

	while (begin != end && isspace(*begin) != 0) {
		begin++;
	}

	while (begin != end && isspace(*end) != 0) {
		end--;
	}

	return std::string{ begin, end };
}
