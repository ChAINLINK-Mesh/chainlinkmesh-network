#include "certificates.hpp"
#include "scope-exit.hpp"
#include <cassert>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <vector>

std::shared_ptr<CertificateManager> CertificateManager::instance = nullptr;

CertificateManager::CertificateManager(
    const std::filesystem::path certificatesFolder)
    : certificatesFolder{ certificatesFolder } {}

std::filesystem::path
CertificateManager::get_certificate_path(NodeID nodeID) const {
	return certificatesFolder / (std::to_string(nodeID) + ".cert");
}

[[nodiscard]] std::optional<Certificate>
CertificateManager::get_certificate(const NodeID nodeID) const {
	// If we haven't yet created the certificates folder, we don't have the node's
	// certificate.
	if (!std::filesystem::exists(certificatesFolder)) {
		return std::nullopt;
	}

	if (const auto certificate = certificatesMap.find(nodeID);
	    certificate != certificatesMap.end()) {
		return certificate->second;
	}

	const auto nodeCertificatePath = get_certificate_path(nodeID);

	// If we don't have the node's certificate file, return empty.
	if (!std::filesystem::exists(nodeCertificatePath)) {
		return std::nullopt;
	}

	std::ifstream nodeCertificate{ nodeCertificatePath,
		                             std::ios::in | std::ios::binary };

	if (!nodeCertificate) {
		return std::nullopt;
	}

	std::vector<unsigned char> nodeCertificateBytes{
		std::istreambuf_iterator<char>{ nodeCertificate },
		std::istreambuf_iterator<char>{}
	};
	nodeCertificate.close();

	const auto* bytePointer = nodeCertificateBytes.data();

	X509* temp;
	d2i_X509(&temp, &bytePointer, nodeCertificateBytes.size());

	Certificate certificate{ nodeID, X509_RAII_SHARED{ temp, &::X509_free } };

	return certificate;
}

void CertificateManager::set_certificate(NodeID nodeID,
                                         const Certificate& certificate) {
	// Create certificate folder if it doesn't exist
	if (!std::filesystem::exists(certificatesFolder)) {
		std::filesystem::create_directory(certificatesFolder);
	}

	unsigned char* certificateBytes = nullptr;
	const int certificateBytesCount =
	    i2d_X509(certificate.x509.get(), &certificateBytes);
	ScopeExit scopeExit1{ [certificateBytes]() { free(certificateBytes); } };

	std::ofstream certificateFile{ get_certificate_path(nodeID) };
	certificateFile.write(reinterpret_cast<char*>(certificateBytes),
	                      certificateBytesCount);

	certificatesMap.try_emplace(nodeID, certificate);
}

[[nodiscard]] std::optional<X509_REQ_RAII>
CertificateManager::generate_certificate_request(
    const CertificateInfo& certificateInfo) {
	assert(certificateInfo.country.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.province.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.city.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.organisation.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.commonName.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.certificateKeyLength <
	       std::numeric_limits<int>::max());
	assert(certificateInfo.validityDuration < std::numeric_limits<int>::max());

	const EVP_PKEY_CTX_RAII rsaCtx{ EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr) };

	// If we failed to generate a valid RSA context.
	if (!rsaCtx) {
		return std::nullopt;
	}

	if (EVP_PKEY_keygen_init(rsaCtx.get()) != 1) {
		return std::nullopt;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(
	        rsaCtx.get(),
	        static_cast<int>(certificateInfo.certificateKeyLength)) <= 0) {
		return std::nullopt;
	}

	EVP_PKEY* tempRSAKey = nullptr;
	if (EVP_PKEY_keygen(rsaCtx.get(), &tempRSAKey) != 1) {
		return std::nullopt;
	}
	const EVP_PKEY_RAII rsaKey{ tempRSAKey };

	// Generate X509 representation
	const X509_RAII_SHARED x509{ X509_new(), &::X509_free };

	// If we failed to initialise the X509 representation.
	if (!x509) {
		return std::nullopt;
	}

	// Set certificate properties
	X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
	X509_gmtime_adj(X509_get_notAfter(x509.get()),
	                static_cast<long>(certificateInfo.validityDuration));

	X509_REQ_RAII x509Req{ X509_REQ_new() };

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
	X509_NAME_RAII x509Name{ X509_NAME_new() };

	if (!x509Name) {
		return std::nullopt;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name.get(), "C", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(
	            certificateInfo.country.data()),
	        static_cast<int>(certificateInfo.country.length()), -1, 0) != 1) {
		return std::nullopt;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name.get(), "ST", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(
	            certificateInfo.province.data()),
	        static_cast<int>(certificateInfo.province.length()), -1, 0) != 1) {
		return std::nullopt;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name.get(), "L", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(certificateInfo.city.data()),
	        static_cast<int>(certificateInfo.city.length()), -1, 0) != 1) {
		return std::nullopt;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name.get(), "O", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(
	            certificateInfo.organisation.data()),
	        static_cast<int>(certificateInfo.organisation.length()), -1,
	        0) != 1) {
		return std::nullopt;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name.get(), "CN", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(
	            certificateInfo.commonName.data()),
	        static_cast<int>(certificateInfo.commonName.length()), -1, 0) != 1) {
		return std::nullopt;
	}

	// Set public key of X509 request
	if (X509_REQ_set_pubkey(x509Req.get(), rsaKey.get()) != 1) {
		return std::nullopt;
	}

	// Set the sign key of X509 request
	if (X509_REQ_sign(x509Req.get(), rsaKey.get(), EVP_sha1()) <= 0) {
		return std::nullopt;
	}

	return x509Req;
}

std::shared_ptr<CertificateManager> CertificateManager::create_instance(
    const std::filesystem::path& certificatesFolder) {
	CertificateManager::instance = std::make_shared<CertificateManager>(
	    CertificateManager{ certificatesFolder });

	return CertificateManager::instance;
}

std::shared_ptr<CertificateManager> CertificateManager::get_instance() {
	// Invalid semantics to request a certificate manager if no instance has yet
	// been created
	assert(CertificateManager::instance);
	return CertificateManager::instance;
}

std::optional<X509_RAII_SHARED>
CertificateManager::decode_pem_certificate(const std::string_view pem) {
	assert(pem.size() < std::numeric_limits<int>::max());

	BIO_RAII bio{ BIO_new(BIO_s_mem()) };

	if (bio == nullptr) {
		return std::nullopt;
	}

	const auto writtenBytes =
	    BIO_write(bio.get(), static_cast<const void*>(pem.data()),
	              static_cast<int>(pem.size()));
	if (writtenBytes < 0 ||
	    static_cast<std::string::size_type>(writtenBytes) != pem.size()) {
		return std::nullopt;
	}

	X509_RAII_SHARED certificate{
		PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), &::X509_free
	};

	if (!certificate) {
		return std::nullopt;
	}

	return certificate;
}

std::optional<X509_REQ_RAII>
CertificateManager::decode_pem_csr(std::string_view pem) {
	assert(pem.size() < std::numeric_limits<int>::max());

	BIO_RAII bio{ BIO_new(BIO_s_mem()) };

	if (bio == nullptr) {
		return std::nullopt;
	}

	const auto writtenBytes =
	    BIO_write(bio.get(), static_cast<const void*>(pem.data()),
	              static_cast<int>(pem.size()));
	if (writtenBytes < 0 ||
	    static_cast<std::string::size_type>(writtenBytes) != pem.size()) {
		return std::nullopt;
	}

	X509_REQ_RAII certificate{ PEM_read_bio_X509_REQ(bio.get(), nullptr, nullptr,
		                                               nullptr) };

	if (!certificate) {
		return std::nullopt;
	}

	return certificate;
}

std::vector<std::string>
CertificateManager::get_subject_attribute(const X509_NAME* const subject,
                                          const int nid) {
	assert(subject != nullptr);

	std::vector<std::string> attributes{};

	int index = -1;
	for (index = X509_NAME_get_index_by_NID(subject, nid, index); index >= 0;
	     index = X509_NAME_get_index_by_NID(subject, nid, index)) {
		const auto* entry = X509_NAME_get_entry(subject, index);
		const auto* entryASNString = X509_NAME_ENTRY_get_data(entry);

		if (entryASNString == nullptr) {
			continue;
		}

		unsigned char* entryCharArray = nullptr;
		const int entryCharArraySize =
		    ASN1_STRING_to_UTF8(&entryCharArray, entryASNString);
		OPENSSL_RAII<unsigned char> entryCharArrayRAII{ entryCharArray };

		if (entryCharArraySize < 0) {
			continue;
		}

		attributes.emplace_back(
		    std::string{ entryCharArrayRAII.get(),
		                 entryCharArrayRAII.get() + entryCharArraySize });
	}

	return attributes;
}
