#include "certificates.hpp"
#include "scope-exit.hpp"
#include <cassert>
#include <fstream>
#include <vector>

std::shared_ptr<CertificateManager> CertificateManager::instance = nullptr;

CertificateManager::CertificateManager(const std::filesystem::path certificatesFolder)
    : certificatesFolder{ std::move(certificatesFolder) } {}

std::filesystem::path CertificateManager::getCertificatePath(const NodeID nodeID) const {
	return certificatesFolder / (std::to_string(nodeID) + ".cert");
}

[[nodiscard]] std::optional<Certificate>
CertificateManager::getCertificate(const NodeID nodeID) const {
	// If we haven't yet created the certificates folder, we don't have the node's certificate.
	if (!std::filesystem::exists(certificatesFolder)) {
		return std::nullopt;
	}

	if (const auto certificate = certificatesMap.find(nodeID); certificate != certificatesMap.end()) {
		return certificate->second;
	}

	const auto nodeCertificatePath = getCertificatePath(nodeID);

	// If we don't have the node's certificate file, return empty.
	if (!std::filesystem::exists(nodeCertificatePath)) {
		return std::nullopt;
	}

	std::ifstream nodeCertificate{ nodeCertificatePath, std::ios::in | std::ios::binary };

	if (!nodeCertificate) {
		return std::nullopt;
	}

	std::vector<unsigned char> nodeCertificateBytes{
		std::istreambuf_iterator<char>{ nodeCertificate }, std::istreambuf_iterator<char>{}
	};
	nodeCertificate.close();

	const auto* bytePointer = nodeCertificateBytes.data();

	X509* temp;
	d2i_X509(&temp, &bytePointer, nodeCertificateBytes.size());

	Certificate certificate{ nodeID, X509_RAII{ temp, X509_free } };

	return certificate;
}

void CertificateManager::setCertificate(const NodeID nodeID, const Certificate certificate) {
	// Create certificate folder if it doesn't exist
	if (!std::filesystem::exists(certificatesFolder)) {
		std::filesystem::create_directory(certificatesFolder);
	}

	unsigned char* certificateBytes = nullptr;
	const int certificateBytesCount = i2d_X509(certificate.x509.get(), &certificateBytes);
	ScopeExit scopeExit1{ [certificateBytes]() { free(certificateBytes); } };

	std::ofstream certificateFile{ getCertificatePath(nodeID) };
	certificateFile.write(reinterpret_cast<char*>(certificateBytes), certificateBytesCount);

	certificatesMap.try_emplace(nodeID, certificate);
}

[[nodiscard]] std::optional<X509_REQ_RAII>
CertificateManager::generateCertificateRequest(const CertificateInfo& certificateInfo) {
	const BN_RAII bn{ BN_new(), ::BN_free };
	const RSA_RAII rsaKey{ RSA_new(), ::RSA_free };

	// If we failed to initialise the RSA key representation.
	if (!bn || !rsaKey) {
		return std::nullopt;
	}

	// Generate RSA key
	if (BN_set_word(bn.get(), RSA_F4) != 1) {
		return std::nullopt;
	}

	if (RSA_generate_key_ex(rsaKey.get(), certificateInfo.certificateKeyLength, bn.get(), nullptr) !=
	    1) {
		return std::nullopt;
	}

	// Generate algorithm-independent private key representation.
	EVP_PKEY_RAII evpKey{ EVP_PKEY_new(), EVP_PKEY_free };

	if (!evpKey) {
		return std::nullopt;
	}

	// Copy RSA key without taking ownership.
	EVP_PKEY_set1_RSA(evpKey.get(), rsaKey.get());

	// Generate X509 representation
	const X509_RAII x509{ X509_new(), ::X509_free };

	// If we failed to initialise the X509 representation.
	if (!x509) {
		return std::nullopt;
	}

	// Set certificate properties
	X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
	X509_gmtime_adj(X509_get_notAfter(x509.get()), certificateInfo.validityDuration);

	X509_REQ_RAII x509Req{ X509_REQ_new(), ::X509_REQ_free };

	// If we failed to initialise the X509 request representation.
	if (!x509Req) {
		return std::nullopt;
	}

	// X509v3 has version number of '2'
	const constexpr std::uint8_t certificateVersion{ 2 };
	if (X509_REQ_set_version(x509Req.get(), certificateVersion) != 1) {
		return std::nullopt;
	}

	// Set certificate subject
	X509_NAME_RAII x509Name{ X509_NAME_new(), ::X509_NAME_free };

	if (!x509Name) {
		return std::nullopt;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name.get(), "C", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(certificateInfo.country.data()),
	        certificateInfo.country.length(), -1, 0) != 1) {
		return std::nullopt;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name.get(), "ST", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(certificateInfo.province.data()),
	        certificateInfo.province.length(), -1, 0) != 1) {
		return std::nullopt;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name.get(), "L", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(certificateInfo.city.data()),
	        certificateInfo.city.length(), -1, 0) != 1) {
		return std::nullopt;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name.get(), "O", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(certificateInfo.organisation.data()),
	        certificateInfo.organisation.length(), -1, 0) != 1) {
		return std::nullopt;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name.get(), "CN", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(certificateInfo.commonName.data()),
	        certificateInfo.commonName.length(), -1, 0) != 1) {
		return std::nullopt;
	}

	// Set public key of X509 request
	if (X509_REQ_set_pubkey(x509Req.get(), evpKey.get()) != 1) {
		return std::nullopt;
	}

	// Set the sign key of X509 request
	if (X509_REQ_sign(x509Req.get(), evpKey.get(), EVP_sha1()) != 1) {
		return std::nullopt;
	}

	return x509Req;
}

std::shared_ptr<CertificateManager>
CertificateManager::createInstance(const std::filesystem::path certificatesFolder) {
	CertificateManager::instance =
	    std::make_shared<CertificateManager>(CertificateManager{ certificatesFolder });

	return CertificateManager::instance;
}

std::shared_ptr<CertificateManager> CertificateManager::getInstance() {
	// Invalid semantics to request a certificate manager if no instance has yet been created
	assert(CertificateManager::instance);
	return CertificateManager::instance;
};