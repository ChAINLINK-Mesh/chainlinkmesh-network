#pragma once

#include <cinttypes>
#include <filesystem>
#include <map>
#include <openssl/x509v3.h>
#include <optional>

using NodeID = std::uint64_t;
using BN_RAII = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using EVP_PKEY_RAII = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using EVP_PKEY_CTX_RAII =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>;
using X509_RAII = std::shared_ptr<X509>;
using X509_REQ_RAII = std::unique_ptr<X509_REQ, decltype(&::X509_REQ_free)>;
using X509_NAME_RAII = std::unique_ptr<X509_NAME, decltype(&::X509_NAME_free)>;

struct Certificate {
	NodeID id;
	X509_RAII x509;
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

protected:
	CertificateManager(std::filesystem::path certificatesFolder);

	std::filesystem::path get_certificate_path(NodeID nodeID) const;

	const std::filesystem::path certificatesFolder;
	mutable std::map<NodeID, Certificate> certificatesMap;

	static std::shared_ptr<CertificateManager> instance;
};
