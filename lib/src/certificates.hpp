#pragma once

#include "types.hpp"
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

	/**
	 * @serialNumber The ID of the node.
	 *
	 *               Should be set for Certificates, but not for
	 *               Certificate-Signing Requests.
	 */
	std::optional<std::uint64_t> serialNumber;
	std::uint64_t validityDuration;
};

template <std::integral Encoding = std::uint8_t>
class GenericCertificateManager {
public:
	using EncodingString = std::basic_string<Encoding>;
	using EncodingStringView = std::basic_string_view<Encoding>;

	/**
	 * @brief Generates an RSA private key.
	 *
	 * @return Either the private key, or std::nullopt if an error occurred.
	 */
	[[nodiscard]] static std::optional<EVP_PKEY_RAII> generate_rsa_key();

	/**
	 * @brief Generates an X509 certificate from the given certificate details
	 *        and private key.
	 *
	 * @param certificateInfo The certificate's details.
	 * @param privateKey The private key to sign the signature with.
	 * @return Either the certificate, or std::nullopt if an error occurred.
	 */
	[[nodiscard]] static std::optional<X509_RAII>
	generate_certificate(const CertificateInfo& certificateInfo,
	                     const EVP_PKEY_RAII& privateKey);

	/**
	 * @brief Generates an X509 certificate-signing request from the given
	 *        certificate details.
	 *
	 * @param certificateInfo The CSR's details.
	 * @param privateKey The private key to sign the CSR with. A value of
	 *                   std::nullopt will generate a default private key.
	 * @return Either the CSR, or std::nullopt if an error occurred.
	 */
	[[nodiscard]] static std::optional<X509_REQ_RAII>
	generate_certificate_request(const CertificateInfo& certificateInfo,
	                             std::optional<EVP_PKEY_RAII> privateKey);

	/**
	 * @brief Converts a private key into a public-key-only form.
	 *
	 * @param privateKey The private key to convert.
	 * @return The public key, or std::nullopt if an error occurred.
	 */
	[[nodiscard]] static std::optional<EVP_PKEY_RAII>
	get_pubkey(const EVP_PKEY_RAII& privateKey);

	/**
	 * @brief Gets a certificate's public key.
	 *
	 * @param certificate which certificate to retrieve the public key for.
	 * @return The public key of the given certificate, or std::nullopt if an
	 *         error occurred.
	 */
	[[nodiscard]] static std::optional<EVP_PKEY_RAII>
	get_certificate_pubkey(const X509_RAII& certificate);

	/**
	 * @brief Gets a certificate-signing-request's public key.
	 *
	 * @param csr Certificate-signing-request to retrieve the public key for.
	 * @return The public key of the given CSR, or std::nullopt if an error
	 *         occurred.
	 */
	[[nodiscard]] static std::optional<EVP_PKEY_RAII>
	get_csr_pubkey(const X509_REQ_RAII& csr);

	/**
	 * @brief Decodes the given PEM bytes into a certificate.
	 *
	 * @param pem certificate in PEM format
	 * @return either the certificate, or std::nullopt if it could not be decoded
	 *         (never nullptr)
	 */
	[[nodiscard]] static std::optional<X509_RAII>
	decode_pem_certificate(EncodingStringView pem);

	/**
	 * @brief Decodes the given PEM bytes into a certificate signing request.
	 *
	 * @param pem CSR in PEM format
	 * @return either the CSR, or std::nullopt if it could not be decoded
	 *         (never nullptr)
	 */
	[[nodiscard]] static std::optional<X509_REQ_RAII>
	decode_pem_csr(EncodingStringView pem);

	/**
	 * @brief Decodes the given PEM bytes into a private key.
	 *
	 * @param pem PEM encoded data, representing a private key
	 * @return either the private key, or std::nullopt if the private key could
	 *         not be decoded
	 */
	[[nodiscard]] static std::optional<EVP_PKEY_RAII>
	decode_pem_private_key(EncodingStringView pem);

	/**
	 * @brief Decodes the given PEM bytes into a public key.
	 *
	 * @param pem PEM encoded data, representing a public key
	 * @return either the public key, or std::nullopt if the public key could not
	 *         be decoded
	 */
	[[nodiscard]] static std::optional<EVP_PKEY_RAII>
	decode_pem_public_key(EncodingStringView pem);

	/**
	 * @brief Decodes a chain of PEM certificates.
	 *
	 * @param pem PEM encoded certificate chain
	 * @return either the list of certificates, or std::nullopt if they could not
	 *         be decoded
	 */
	[[nodiscard]] static std::optional<std::vector<X509_RAII>>
	decode_pem_certificate_chain(EncodingStringView pem);

	/**
	 * @brief Retrieves a list of values specified for a given subject attribute
	 *        Numeric ID.
	 *
	 * @param subject the OpenSSL subject name. Doesn't take an owning copy of the
	 *        data.
	 * @param nid the subject attribute Numeric ID
	 * @return a list of all values specified for this attribute
	 */
	[[nodiscard]] static std::vector<std::string>
	get_subject_attribute(const X509_NAME* subject, int nid);

	/**
	 * @brief Sets an attribute's value for an X509 subject name.
	 *
	 *        Will create new name entries if this NID has not been previously
	 * set.
	 *
	 * @param subject The subject name.
	 * @param nid The ID of the attribute to modify.
	 * @param attributeValue The UTF-8 encoded value to set this attribute to.
	 * @return Whether the operation was a success.
	 */
	static bool set_subject_attribute(X509_NAME* subject, int nid,
	                                  const EncodingStringView& attributeValue);

	/**
	 * @brief Encodes an X509 certificate to PEM format.
	 *
	 * @param x509 the X509 certificate to encode
	 * @return the PEM encoding of the given X509 certificate
	 */
	[[nodiscard]] static EncodingString encode_pem(const X509_RAII& x509);

	/**
	 * @brief Encodes an X509 CSR to PEM format.
	 *
	 * @param x509 the X509 CSR to encode.
	 * @return the PEM encoding of the given X509 CSR
	 */
	[[nodiscard]] static EncodingString encode_pem(const X509_REQ_RAII& x509Req);

	/**
	 * @brief Encodes an X509 certificate chain to PEM format, in the order
	 * provided.
	 *
	 * @param certificateChain The chain of X509 certificates to encode.
	 * @return The PEM encoding of the given certificate chain.
	 */
	[[nodiscard]] static EncodingString
	encode_pem(const std::vector<X509_RAII>& certificateChain);

	/**
	 * @brief Encodes a private key to PEM format.
	 *
	 * @param pkey the private key to encode
	 * @return the PEM encoding of the given private key
	 */
	[[nodiscard]] static EncodingString encode_pem(const EVP_PKEY_RAII& pkey);

	/**
	 * @brief Signs a CSR with the given certificate and keys.
	 *
	 * @param req the X509 CSR request to sign
	 * @param caCert the CA X509 certificate to use to sign this
	 * @param caKey the CA X509 certificate private key
	 * @param validityDurationSeconds how many seconds the signed certificate
	 *                                should be valid for
	 * @return either the signed certificate, or std::nullopt if the certificate
	 *         could not be signed
	 */
	[[nodiscard]] static std::optional<X509_RAII>
	sign_csr(const X509_REQ_RAII& req, const X509_RAII& caCert,
	         const EVP_PKEY_RAII& caKey, std::uint64_t validityDurationSeconds);

	/**
	 * @brief Signs the given data with the private key.
	 *
	 * @param privateKey The private-key to sign this data with.
	 * @param data The data to sign.
	 * @return Either the signature, or std::nullopt if that failed.
	 */
	[[nodiscard]] static std::optional<std::vector<Encoding>>
	sign_data(const EVP_PKEY_RAII& privateKey,
	          const std::span<const Encoding>& data);

	/**
	 * @brief Checks that the given public key signed the data with the signature.
	 *
	 * @param publicKey Public key of expected signatory.
	 * @param data The data signed.
	 * @param signature The signature to verify against.
	 * @return Either a boolean representing if the signature matches, or
	 *         std::nullopt if a failure occurred.
	 */
	[[nodiscard]] static std::optional<bool>
	check_signature(const EVP_PKEY_RAII& publicKey,
	                const std::span<const Encoding>& data,
	                const std::span<const Encoding>& signature);

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
bool operator==(const X509& a, const X509& b);
bool operator==(const EVP_PKEY& a, const EVP_PKEY& b);
