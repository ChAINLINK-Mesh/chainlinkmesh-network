#pragma once

#include <cassert>
#include <concepts>
#include <cstdint>
#include <memory>
#include <openssl/x509.h>
#include <string>

using ByteString = std::basic_string<std::uint8_t>;
using ByteStringView = std::basic_string_view<std::uint8_t>;

/*
 * This type is designed to replicate the functionality of std::unique_ptr, whilst still being copyable.
 * This is useful, as it allows members of this type to be used without requiring explicit copy or constructor
 * implementations. Therefore, depedent classes can still be designed as aggregate types.
 *
 * This is also useful, in spite of std::shared_ptr, because OpenSSL's objects are internally reference counted too, so
 * we can avoid the overhead of duplicating this reference counting behaviour.
 */
template <typename Type, typename Deleter, typename Copier>
requires std::default_initializable<Copier> && std::invocable<Copier, Type*>
struct CopyableUniquePtr : public std::unique_ptr<Type, Deleter> {
	CopyableUniquePtr(const CopyableUniquePtr<Type, Deleter, Copier>&
	                      other) noexcept(noexcept(Copier{}(other.get())))
	    : std::unique_ptr<Type, Deleter>{ Copier{}(other.get()) } {}

	using std::unique_ptr<Type, Deleter>::unique_ptr;

	CopyableUniquePtr<Type, Deleter, Copier>&
	operator=(const CopyableUniquePtr<Type, Deleter, Copier>& other) noexcept(
	    noexcept(Copier{}(other.get()))) {
		this->reset(Copier{}(other.get()));
	}

	CopyableUniquePtr<Type, Deleter, Copier>& operator=(
	    CopyableUniquePtr<Type, Deleter, Copier>&& other) noexcept = default;
};

template <auto function, typename Type>
requires std::invocable<decltype(function), Type*>
struct FunctionCopier {
	Type* operator()(Type* ptr) const {
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
using EVP_PKEY_RAII = std::unique_ptr<EVP_PKEY, FunctionDeleter<EVP_PKEY_free>>;
using EVP_PKEY_CTX_RAII =
    std::unique_ptr<EVP_PKEY_CTX, FunctionDeleter<EVP_PKEY_CTX_free>>;
using X509_RAII_SHARED = std::shared_ptr<X509>;
using X509_RAII = CopyableUniquePtr<X509, FunctionDeleter<X509_free>,
                                    FunctionCopier<X509_dup, X509>>;
using X509_REQ_RAII = std::unique_ptr<X509_REQ, FunctionDeleter<X509_REQ_free>>;
using X509_NAME_RAII =
    std::unique_ptr<X509_NAME, FunctionDeleter<X509_NAME_free>>;

template <typename Type>
using OPENSSL_RAII = std::unique_ptr<Type, OpenSSLDeleter<Type>>;

