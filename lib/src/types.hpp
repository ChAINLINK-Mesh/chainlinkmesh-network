#pragma once

#include "error.hpp"

#include <Poco/Net/IPAddress.h>
#include <Poco/Net/SocketAddress.h>
#include <cassert>
#include <concepts>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

extern "C" {
#include <openssl/x509.h>
}

using ByteString = std::basic_string<std::uint8_t>;
using ByteStringView = std::basic_string_view<std::uint8_t>;

/*
 * This type is designed to replicate the functionality of std::unique_ptr,
 * whilst still being copyable. This is useful, as it allows members of this
 * type to be used without requiring explicit copy or constructor
 * implementations. Therefore, depedent classes can still be designed as
 * aggregate types.
 *
 * This is also useful, in spite of std::shared_ptr, because OpenSSL's objects
 * are internally reference counted too, so we can avoid the overhead of
 * duplicating this reference counting behaviour.
 */
template <typename Type, typename Deleter, typename Copier>
requires std::default_initializable<Copier> &&
    std::invocable<const Copier, Type*>
struct CopyableUniquePtr : public std::unique_ptr<Type, Deleter> {
	CopyableUniquePtr(const CopyableUniquePtr<Type, Deleter, Copier>&
	                      other) noexcept(noexcept(Copier{}(other.get())))
	    : std::unique_ptr<Type, Deleter>{ Copier{}(other.get()) } {}

	CopyableUniquePtr(CopyableUniquePtr<Type, Deleter, Copier>&& other) noexcept(
	    noexcept(std::unique_ptr<Type, Deleter>{ std::move(other) }))
	    : std::unique_ptr<Type, Deleter>{ std::move(other) } {}

	CopyableUniquePtr(Type* value) noexcept(
	    noexcept(std::unique_ptr<Type, Deleter>{ value }))
	    : std::unique_ptr<Type, Deleter>{ value } {}

	CopyableUniquePtr() noexcept(noexcept(std::unique_ptr<Type, Deleter>{}))
	    : std::unique_ptr<Type, Deleter>{} {}

	CopyableUniquePtr<Type, Deleter, Copier>&
	operator=(const CopyableUniquePtr<Type, Deleter, Copier>& other) noexcept(
	    noexcept(Copier{}(other.get()))) {
		this->reset(Copier{}(other.get()));
		return *this;
	}

	CopyableUniquePtr<Type, Deleter, Copier>& operator=(
	    CopyableUniquePtr<Type, Deleter, Copier>&& other) noexcept = default;
};

template <typename T, typename P>
concept copier = requires(T t, P* p) {
	{ t(p) } -> std::same_as<P*>;
};

template <auto function>
struct FunctionCopier {
	template <typename Type>
	requires copier<decltype(function), Type> Type* operator()(Type* ptr) const {
		if (ptr == nullptr) {
			return nullptr;
		}

		Type* copied = function(ptr);
		assert(copied != nullptr);
		return copied;
	}
};

/*
 * Thanks to krzaq for this elegant stateless functor implementation:
 * https://dev.krzaq.cc/post/you-dont-need-a-stateful-deleter-in-your-unique_ptr-usually/
 */
template <auto function>
struct FunctionDeleter {
	template <typename... Params>
	auto operator()(Params&&... params) const {
		return function(std::forward<Params...>(params...));
	}
};

template <typename Type>
struct OpenSSLDeleter {
	auto operator()(Type* pointer) const {
		return OPENSSL_free(pointer);
	}
};

using NodeID = std::uint64_t;
using BIO_RAII = std::unique_ptr<BIO, FunctionDeleter<BIO_free>>;
using BN_RAII = std::unique_ptr<BIGNUM, FunctionDeleter<BN_free>>;
using EVP_PKEY_RAII =
    CopyableUniquePtr<EVP_PKEY, FunctionDeleter<EVP_PKEY_free>,
                      FunctionCopier<EVP_PKEY_dup>>;
using EVP_PKEY_CTX_RAII =
    std::unique_ptr<EVP_PKEY_CTX, FunctionDeleter<EVP_PKEY_CTX_free>>;
using EVP_MD_CTX_RAII =
    std::unique_ptr<EVP_MD_CTX, FunctionDeleter<EVP_MD_CTX_free>>;
using X509_RAII_SHARED = std::shared_ptr<X509>;
using X509_RAII = CopyableUniquePtr<X509, FunctionDeleter<X509_free>,
                                    FunctionCopier<X509_dup>>;
using X509_REQ_RAII = std::unique_ptr<X509_REQ, FunctionDeleter<X509_REQ_free>>;
using X509_NAME_RAII =
    std::unique_ptr<X509_NAME, FunctionDeleter<X509_NAME_free>>;

template <typename Type>
using OPENSSL_RAII = std::unique_ptr<Type, OpenSSLDeleter<Type>>;

const constexpr std::uint16_t SHA256_DIGEST_SIZE = 32;
const constexpr std::uint16_t SHA256_SIGNATURE_SIZE = 256;
using SHA256_Hash = std::array<std::uint8_t, SHA256_DIGEST_SIZE>;
using SHA256_Signature = std::array<std::uint8_t, SHA256_SIGNATURE_SIZE>;

class Host {
public:
	/**
	 * @brief Constructs a host from either
	 *         * a socket address IP:Port pair,
	 *         * an IP
	 *         * a DNS hostname
	 *
	 * @param host the host identifier, which should not be empty
	 */
	explicit Host(std::string host);
	explicit Host(Poco::Net::IPAddress host) noexcept;
	explicit Host(const Poco::Net::SocketAddress& host) noexcept;

	Host(const Host& other) = default;
	Host(Host&& other) = default;

	Host& operator=(const Host& other) = default;
	Host& operator=(Host&& other) = default;

	/**
	 * @brief Resolves the given host to an IP address. Will not attempt to
	 *        re-resolve addresses.
	 *
	 * @return The host's IP address.
	 */
	operator Poco::Net::IPAddress() const;

	/**
	 * @brief Resolves the given host to an IP address. Returns any exceptions
	 *        encountered. Will not attempt to re-resolve addresses.
	 *
	 * @return The host's IP address or any exceptions encountered.
	 */
	Expected<Poco::Net::IPAddress> resolve() const noexcept;

	/**
	 * @brief Checks whether the host is valid. Will not attempt to re-resolve
	 * addresses.
	 *
	 * @return True if the host resolves (i.e. is valid).
	 */
	[[nodiscard]] explicit operator bool() const noexcept;

	/**
	 * @brief Gets the least-resolved name possible.
	 *
	 * @return The DNS hostname, or the IP address if the DNS hostname was never
	 *         provided.
	 */
	explicit operator std::string() const noexcept;

	/**
	 * @brief Gets the port associated with this host.
	 *
	 * @return The associated port, or std::nullopt if no port has been provided.
	 */
	std::optional<std::uint16_t> port() const noexcept;

protected:
	/**
	 * @brief Resolves the DNS hostname into an IP address. Will re-resolve
	 *        domains, even if IP address is already known.
	 *
	 * @return The IP address if the DNS hostname resolved correctly, otherwise
	 *         the exception which caused the failure.
	 */
	Expected<Poco::Net::IPAddress> reresolve() const noexcept;

	mutable std::optional<Poco::Net::IPAddress> ip;
	std::optional<std::string> dns;
	std::optional<std::uint16_t> portNumber;
};

/**
 * @brief A std::unique_ptr alternative with optional ownership semantics.
 *
 * @tparam Type The type to wrap.
 */
template <typename Type>
class OptionallyOwned {
public:
	/**
	 * @brief Takes a value without ownership.
	 *
	 * @param value Value to represent. Must persist for lifetime of wrapper.
	 */
	explicit OptionallyOwned(Type& value) : isOwner{ false }, value{ &value } {}

	/**
	 * @brief Takes a value by r-value reference.
	 *
	 * @param value Value to represent.
	 */
	explicit OptionallyOwned(
	    Type&& value) requires std::is_move_constructible_v<Type>
	    : isOwner{ true }, value{ new Type{ std::move(value) } } {}

	/**
	 * @brief Takes ownership of a value from a std::unique_ptr wrapper.
	 *
	 * @param value Value to represent.
	 */
	explicit OptionallyOwned(std::unique_ptr<Type> value)
	    : isOwner{ true }, value{ value.get() } {
		value.release();
	}

	/**
	 * @brief Takes control of an existing optionally-owned value.
	 *
	 * @param other The other value to take control of.
	 */
	OptionallyOwned(OptionallyOwned<Type>&& other) noexcept
	    : isOwner{ other.isOwner }, value{ other.value } {}

	virtual ~OptionallyOwned() {
		if (isOwner) {
			delete value;
		}
	}

	OptionallyOwned& operator=(OptionallyOwned<Type>&& other) noexcept {
		if (isOwner) {
			delete value;
		}

		this->isOwner = other.isOwner;
		this->value = other.value;

		other.isOwner = false;
		other.value = nullptr;

		return *this;
	}

	/**
	 * @brief Constructs an owned copy from constructor arguments.
	 *
	 * @tparam ConstructorParams The constructor parameter types.
	 * @param params The arguments to the underlying type's constructor.
	 */
	template <typename... ConstructorParams>
	static OptionallyOwned<Type> make(ConstructorParams... params) {
		return OptionallyOwned<Type>{ std::make_unique<Type>(
			  std::forward<ConstructorParams>(params)...) };
	}

	operator Type&() {
		return *value;
	}

	operator const Type&() const {
		return *value;
	}

protected:
	bool isOwner;
	Type* value = nullptr;
};
