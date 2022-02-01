#pragma once

#include <cinttypes>
#include <filesystem>
#include <map>
#include <openssl/x509v3.h>
#include <optional>

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
using X509_REQ_RAII = std::unique_ptr<X509_REQ, FunctionDeleter<X509_REQ_free>>;
using X509_NAME_RAII =
    std::unique_ptr<X509_NAME, FunctionDeleter<X509_NAME_free>>;

template <typename Type>
using OPENSSL_RAII = std::unique_ptr<Type, OpenSSLDeleter<Type>>;

struct Certificate {
	NodeID id;
	X509_RAII_SHARED x509;
};

struct CertificateInfo {
	std::uint32_t certificateKeyLength;
	// Encoded in UTF-8 format.
	std::string_view country, province, city, organisation, commonName;
	std::uint64_t validityDuration;
};

class CertificateManager {
public:
	CertificateManager(CertificateManager&& other) = default;
	~CertificateManager() = default;

	[[nodiscard]] std::optional<Certificate> get_certificate(NodeID nodeID) const;
	void set_certificate(NodeID nodeID, const Certificate& certificate);

	// Generates a X509v3 certificate
	[[nodiscard]] static std::optional<X509_REQ_RAII>
	generate_certificate_request(const CertificateInfo& certificateInfo);

	static std::shared_ptr<CertificateManager>
	create_instance(const std::filesystem::path& certificatesFolder);
	static std::shared_ptr<CertificateManager> get_instance();

	/**
	 * Decodes a PEM certificate representation.
	 * @param pem certificate in PEM format
	 * @return either std::nullopt or std::unique_pointer to the certificate
	 * structure (never nullptr)
	 */
	static std::optional<X509_RAII_SHARED>
	decode_pem_certificate(std::string_view pem);

	/**
	 * Decodes a certificate signing request in PEM representation.
	 * @param pem CSR in PEM format
	 * @return either std::nullopt or std::unique_pointer to the CSR structure
	 * (never nullptr)
	 */
	static std::optional<X509_REQ_RAII> decode_pem_csr(std::string_view pem);

protected:
	CertificateManager(std::filesystem::path certificatesFolder);

	std::filesystem::path get_certificate_path(NodeID nodeID) const;

	const std::filesystem::path certificatesFolder;
	mutable std::map<NodeID, Certificate> certificatesMap;

	static std::shared_ptr<CertificateManager> instance;
};
