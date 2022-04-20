#pragma once

#include "utilities.hpp"

#include <cinttypes>
#include <filesystem>
#include <map>
#include <optional>
#include <vector>

extern "C" {
#include <openssl/x509v3.h>
}

struct Certificate {
	NodeID id;
	X509_RAII_SHARED x509;
};

struct CertificateInfo {
	// Encoded in UTF-8 format.
	std::string country, province, city, organisation, commonName, userID;
	std::uint64_t validityDuration;
};

template <std::integral Encoding = std::uint8_t>
class GenericCertificateManager {
public:
	using EncodingString = std::basic_string<Encoding>;
	using EncodingStringView = std::basic_string_view<Encoding>;

	[[nodiscard]] static std::optional<EVP_PKEY_RAII> generate_rsa_key();

	// Generates a X509v3 certificate
	[[nodiscard]] static std::optional<X509_RAII>
	generate_certificate(const CertificateInfo& certificateInfo,
	                     const EVP_PKEY_RAII& rsaKey);

	// Generates a X509v3 certificate-signing-request
	[[nodiscard]] static std::optional<X509_REQ_RAII>
	generate_certificate_request(const CertificateInfo& certificateInfo);

	static std::shared_ptr<GenericCertificateManager>
	create_instance(const std::filesystem::path& certificatesFolder);
	static std::shared_ptr<GenericCertificateManager> get_instance();

	/**
	 * @brief Gets a certificate's public key.
	 *
	 * @param certificate which certificate to retrieve the public key for.
	 * @return the public key of the given certificate
	 */
	static std::optional<EVP_PKEY_RAII>
	get_certificate_pubkey(const X509_RAII& certificate);

	/**
	 * @brief Decodes the given PEM bytes into a certificate.
	 *
	 * @param pem certificate in PEM format
	 * @return either the certificate, or std::nullopt if it could not be decoded
	 *         (never nullptr)
	 */
	static std::optional<X509_RAII>
	decode_pem_certificate(EncodingStringView pem);

	/**
	 * @brief Decodes the given PEM bytes into a certificate signing request.
	 *
	 * @param pem CSR in PEM format
	 * @return either the CSR, or std::nullopt if it could not be decoded
	 *         (never nullptr)
	 */
	static std::optional<X509_REQ_RAII> decode_pem_csr(EncodingStringView pem);

	/**
	 * @brief Decodes the given PEM bytes into a private key.
	 *
	 * @param pem PEM encoded data, representing a private key
	 * @return either the private key, or std::nullopt if the private key could
	 *         not be decoded
	 */
	static std::optional<EVP_PKEY_RAII>
	decode_pem_private_key(EncodingStringView pem);

	/**
	 * @brief Decodes the given PEM bytes into a public key.
	 *
	 * @param pem PEM encoded data, representing a public key
	 * @return either the public key, or std::nullopt if the public key could not
	 *         be decoded
	 */
	static std::optional<EVP_PKEY_RAII>
	decode_pem_public_key(EncodingStringView pem);

	/**
	 * @brief Retrieves a list of values specified for a given subject attribute
	 *        Numeric ID.
	 *
	 * @param subject the OpenSSL subject name. Doesn't take an owning copy of the
	 *        data.
	 * @param nid the subject attribute Numeric ID
	 * @return a list of all values specified for this attribute
	 */
	static std::vector<std::string>
	get_subject_attribute(const X509_NAME* subject, int nid);

	/**
	 * @brief Encodes an X509 certificate to PEM format.
	 *
	 * @param x509 the X509 certificate to encode
	 * @return the PEM encoding of the given X509 certificate
	 */
	static EncodingString encode_pem(const X509_RAII& x509);

	/**
	 * @brief Encodes an X509 CSR to PEM format.
	 *
	 * @param x509 the X509 CSR to encode.
	 * @return the PEM encoding of the given X509 CSR
	 */
	static EncodingString encode_pem(const X509_REQ_RAII& x509Req);

	/**
	 * @brief Encodes a private key to PEM format.
	 *
	 * @param pkey the private key to encode
	 * @return the PEM encoding of the given private key
	 */
	static EncodingString encode_pem(const EVP_PKEY_RAII& pkey);

	/**
	 * @brief Signs a CSR with the given certificate and keys.
	 *
	 * @param req the X509 CSR request to sign
	 * @param caCert what X509 certificate to use to sign this
	 * @param key the X509 certificate private key
	 * @param validityDurationSeconds how many seconds the signed certificate
	 *                                should be valid for
	 * @return either the signed certificate, or std::nullopt if the certificate
	 *         could not be signed
	 */
	static std::optional<X509_RAII>
	sign_csr(X509_REQ_RAII& req, const X509_RAII& caCert,
	         const EVP_PKEY_RAII& key, std::uint64_t validityDurationSeconds);

	// Enforce 2048-bit RSA keys
	static const constexpr std::uint32_t KEY_LENGTH = 2048;

protected:
	/**
	 * @brief Sets up an X509 subject name structure according to the certificate
	 * information provided.
	 *
	 * @param name the X509 subject name to setup
	 * @param certificateInfo the certificate details
	 * @return whether the operation was a success
	 */
	static bool
	x509_set_name_from_certificate_info(X509_NAME* name,
	                                    const CertificateInfo& certificateInfo);

	// X509v3 has version number of '2'
	static const constexpr std::uint8_t DEFAULT_CERTIFICATE_VERSION{ 2 };
};

using CertificateManager = GenericCertificateManager<>;

bool operator==(const X509_REQ& a, const X509_REQ& b);
