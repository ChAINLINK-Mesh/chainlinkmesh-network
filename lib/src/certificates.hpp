#pragma once

#include "utilities.hpp"
#include <cinttypes>
#include <filesystem>
#include <map>
#include <openssl/x509v3.h>
#include <optional>
#include <vector>

struct Certificate {
	NodeID id;
	X509_RAII_SHARED x509;
};

struct CertificateInfo {
	std::uint32_t certificateKeyLength;
	// Encoded in UTF-8 format.
	std::string country, province, city, organisation, commonName, userID;
	std::uint64_t validityDuration;
};

class CertificateManager {
public:
	CertificateManager(CertificateManager&& other) = default;
	~CertificateManager() = default;

	[[nodiscard]] std::optional<Certificate> get_certificate(NodeID nodeID) const;
	void set_certificate(NodeID nodeID, const Certificate& certificate);

	[[nodiscard]] static std::optional<EVP_PKEY_RAII>
	generate_rsa_key(std::uint32_t keyLength);

	// Generates a X509v3 certificate
	[[nodiscard]] static std::optional<X509_RAII>
	generate_certificate(const CertificateInfo& certificateInfo,
	                     const EVP_PKEY_RAII& rsaKey);

	// Generates a X509v3 certificate-signing-request
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
	static std::optional<X509_RAII> decode_pem_certificate(ByteStringView pem);

	/**
	 * Decodes a certificate signing request in PEM representation.
	 * @param pem CSR in PEM format
	 * @return either std::nullopt or std::unique_pointer to the CSR structure
	 * (never nullptr)
	 */
	static std::optional<X509_REQ_RAII> decode_pem_csr(ByteStringView pem);

	/**
	 * @brief Decodes the given PEM bytes into a private key.
	 *
	 * @param pem PEM encoded data, representing a private key
	 * @return either the private key, or std::nullopt if the private key could
	 *         not be decoded
	 */
	static std::optional<EVP_PKEY_RAII>
	decode_pem_private_key(ByteStringView pem);

	/**
	 * Retrieves a list of values specified for a given subject attribute Numeric
	 * ID.
	 *
	 * @param subject the OpenSSL subject name. Doesn't take an owning copy of the
	 *                data.
	 * @param nid the subject attribute Numeric ID
	 * @return a list of all values specified for this attribute
	 */
	static std::vector<std::string>
	get_subject_attribute(const X509_NAME* subject, int nid);

	/**
	 * Encodes an X509 certificate to PEM format.
	 *
	 * @param x509 the X509 certificate to encode
	 * @return the PEM encoding of the given X509 certificate
	 */
	static ByteString encode_pem(const X509_RAII& x509);

	/**
	 * Encodes an X509 CSR to PEM format.
	 *
	 * @param x509 the X509 CSR to encode
	 * @return the PEM encoding of the given X509 CSR
	 */
	static ByteString encode_pem(const X509_REQ_RAII& x509Req);

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

protected:
	CertificateManager(std::filesystem::path certificatesFolder);

	std::filesystem::path get_certificate_path(NodeID nodeID) const;

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

	const std::filesystem::path certificatesFolder;
	mutable std::map<NodeID, Certificate> certificatesMap;

	static std::shared_ptr<CertificateManager> instance;

	// X509v3 has version number of '2'
	static const constexpr std::uint8_t DEFAULT_CERTIFICATE_VERSION{ 2 };
};

bool operator==(const X509_REQ& a, const X509_REQ& b);
