#include "certificates.hpp"
#include "debug.h"
#include "types.hpp"
#include "utilities.hpp"
#include <cassert>
#include <cstring>
#include <fstream>
#include <limits>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <optional>
#include <vector>

std::shared_ptr<CertificateManager> CertificateManager::instance = nullptr;

CertificateManager::CertificateManager(std::filesystem::path certificatesFolder)
    : certificatesFolder{ std::move(certificatesFolder) } {}

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

	assert(nodeCertificateBytes.size() < std::numeric_limits<long>::max());

	const auto* bytePointer = nodeCertificateBytes.data();

	X509* temp;
	d2i_X509(&temp, &bytePointer, static_cast<long>(nodeCertificateBytes.size()));

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
	OPENSSL_RAII<unsigned char> scopeExit1{ certificateBytes };

	std::ofstream certificateFile{ get_certificate_path(nodeID) };
	certificateFile.write(reinterpret_cast<char*>(certificateBytes),
	                      certificateBytesCount);

	certificatesMap.try_emplace(nodeID, certificate);
}

[[nodiscard]] std::optional<EVP_PKEY_RAII>
CertificateManager::generate_rsa_key(std::uint32_t keyLength) {
	const EVP_PKEY_CTX_RAII rsaCtx{ EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr) };

	// If we failed to generate a valid RSA context.
	if (!rsaCtx) {
		return std::nullopt;
	}

	if (EVP_PKEY_keygen_init(rsaCtx.get()) != 1) {
		return std::nullopt;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(rsaCtx.get(),
	                                     static_cast<int>(keyLength)) <= 0) {
		return std::nullopt;
	}

	EVP_PKEY* tempRSAKey = nullptr;
	if (EVP_PKEY_keygen(rsaCtx.get(), &tempRSAKey) != 1) {
		return std::nullopt;
	}

	return EVP_PKEY_RAII{ tempRSAKey };
}

[[nodiscard]] std::optional<X509_RAII>
CertificateManager::generate_certificate(const CertificateInfo& certificateInfo,
                                         const EVP_PKEY_RAII& rsaKey) {
	assert(certificateInfo.certificateKeyLength <
	       std::numeric_limits<int>::max());
	assert(certificateInfo.validityDuration < std::numeric_limits<long>::max());

	if (debug_check(static_cast<int>(certificateInfo.certificateKeyLength) !=
	                EVP_PKEY_get_bits(rsaKey.get()))) {
		return std::nullopt;
	}

	if (!rsaKey) {
		return std::nullopt;
	}

	// Generate X509 representation
	X509_RAII x509{ X509_new() };

	// If we failed to initialise the X509 representation.
	if (!x509) {
		return std::nullopt;
	}

	// Set certificate properties
	X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(x509.get()),
	                static_cast<long>(certificateInfo.validityDuration));

	if (X509_set_pubkey(x509.get(), rsaKey.get()) != 1) {
		return std::nullopt;
	}

	auto* x509Name = X509_get_subject_name(x509.get());

	if (x509Name == nullptr) {
		return std::nullopt;
	}

	if (!x509_set_name_from_certificate_info(x509Name, certificateInfo)) {
		return std::nullopt;
	}

	if (X509_set_issuer_name(x509.get(), x509Name) != 1) {
		return std::nullopt;
	}

	if (X509_sign(x509.get(), rsaKey.get(), EVP_sha256()) == 0) {
		return std::nullopt;
	}

	return x509;
}

[[nodiscard]] std::optional<X509_REQ_RAII>
CertificateManager::generate_certificate_request(
    const CertificateInfo& certificateInfo) {
	assert(certificateInfo.certificateKeyLength <
	       std::numeric_limits<int>::max());
	assert(certificateInfo.validityDuration < std::numeric_limits<long>::max());

	// Generate RSA key
	const auto rsaKey = generate_rsa_key(certificateInfo.certificateKeyLength);

	if (!rsaKey) {
		return std::nullopt;
	}

	X509_REQ_RAII x509Req{ X509_REQ_new() };

	// If we failed to initialise the X509 request representation.
	if (!x509Req) {
		return std::nullopt;
	}

	if (X509_REQ_set_version(x509Req.get(),
	                         CertificateManager::DEFAULT_CERTIFICATE_VERSION) !=
	    1) {
		return std::nullopt;
	}

	// Set certificate subject
	auto* x509Name{ X509_REQ_get_subject_name(x509Req.get()) };

	if (x509Name == nullptr) {
		return std::nullopt;
	}

	if (!x509_set_name_from_certificate_info(x509Name, certificateInfo)) {
		return std::nullopt;
	}

	// Set public key of X509 request
	if (X509_REQ_set_pubkey(x509Req.get(), rsaKey->get()) != 1) {
		return std::nullopt;
	}

	// Set the sign key of X509 request
	if (X509_REQ_sign(x509Req.get(), rsaKey->get(), EVP_sha1()) <= 0) {
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

std::optional<X509_RAII>
CertificateManager::decode_pem_certificate(const ByteStringView pem) {
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

	X509_RAII certificate{ PEM_read_bio_X509(bio.get(), nullptr, nullptr,
		                                       nullptr) };

	if (!certificate) {
		return std::nullopt;
	}

	return certificate;
}

std::optional<X509_REQ_RAII>
CertificateManager::decode_pem_csr(ByteStringView pem) {
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

std::optional<EVP_PKEY_RAII>
CertificateManager::decode_pem_private_key(ByteStringView pem) {
	assert(pem.size() < std::numeric_limits<int>::max());

	BIO_RAII pemBIO{ BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())) };

	return EVP_PKEY_RAII{ PEM_read_bio_PrivateKey(pemBIO.get(), nullptr, nullptr,
		                                            nullptr) };
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

ByteString CertificateManager::encode_pem(const X509_RAII& x509) {
	BIO_RAII bio{ BIO_new(BIO_s_mem()) };

	if (PEM_write_bio_X509(bio.get(), x509.get()) == 0) {
		throw std::invalid_argument{ "PEM encoding failure" };
	};

	char* data = nullptr;
	const auto pemSize = BIO_get_mem_data(bio.get(), &data);

	if (pemSize <= 0) {
		throw std::invalid_argument{ "PEM buffer read error" };
	}

	return ByteString{ data, data + pemSize };
}

ByteString CertificateManager::encode_pem(const X509_REQ_RAII& x509Req) {
	BIO_RAII bio{ BIO_new(BIO_s_mem()) };

	if (PEM_write_bio_X509_REQ(bio.get(), x509Req.get()) == 0) {
		throw std::invalid_argument{ "PEM encoding failure" };
	};

	char* data = nullptr;
	const auto pemSize = BIO_get_mem_data(bio.get(), &data);

	if (pemSize <= 0) {
		throw std::invalid_argument{ "PEM buffer read error" };
	}

	return ByteString{ data, data + pemSize };
}

std::optional<X509_RAII>
CertificateManager::sign_csr(X509_REQ_RAII& req, const X509_RAII& caCert,
                             const EVP_PKEY_RAII& key,
                             const std::uint64_t validityDurationSeconds) {
	assert(validityDurationSeconds < std::numeric_limits<long>::max());

	X509_RAII signedReq{ X509_new() };

	if (!signedReq) {
		return std::nullopt;
	}

	X509_set_version(signedReq.get(),
	                 CertificateManager::DEFAULT_CERTIFICATE_VERSION);
	const auto* const caCertPtr = caCert.get();
	auto* const caSN = X509_get_subject_name(caCertPtr);

	if (caSN == nullptr) {
		return std::nullopt;
	}

	X509_set_issuer_name(signedReq.get(), caSN);

	X509_gmtime_adj(X509_getm_notBefore(signedReq.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(signedReq.get()),
	                static_cast<long>(validityDurationSeconds));

	auto* const reqSN = X509_REQ_get_subject_name(req.get());

	if (reqSN == nullptr) {
		return std::nullopt;
	}

	X509_set_subject_name(signedReq.get(), reqSN);

	EVP_PKEY_RAII reqPubKey{ X509_REQ_get_pubkey(req.get()) };

	if (reqPubKey == nullptr) {
		return std::nullopt;
	}

	X509_set_pubkey(signedReq.get(), reqPubKey.get());

	if (X509_sign(signedReq.get(), key.get(), EVP_sha256()) == 0) {
		return std::nullopt;
	}

	return signedReq;
}

bool CertificateManager::x509_set_name_from_certificate_info(
    X509_NAME* x509Name, const CertificateInfo& certificateInfo) {
	assert(certificateInfo.country.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.province.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.city.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.organisation.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.commonName.size() < std::numeric_limits<int>::max());

	if (X509_NAME_add_entry_by_txt(
	        x509Name, "C", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(
	            certificateInfo.country.data()),
	        static_cast<int>(certificateInfo.country.length()), -1, 0) != 1) {
		return false;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name, "ST", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(
	            certificateInfo.province.data()),
	        static_cast<int>(certificateInfo.province.length()), -1, 0) != 1) {
		return false;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name, "L", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(certificateInfo.city.data()),
	        static_cast<int>(certificateInfo.city.length()), -1, 0) != 1) {
		return false;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name, "O", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(
	            certificateInfo.organisation.data()),
	        static_cast<int>(certificateInfo.organisation.length()), -1,
	        0) != 1) {
		return false;
	}

	if (X509_NAME_add_entry_by_txt(
	        x509Name, "CN", MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(
	            certificateInfo.commonName.data()),
	        static_cast<int>(certificateInfo.commonName.length()), -1, 0) != 1) {
		return false;
	}

	return true;
}

bool operator==(const X509_REQ& a, const X509_REQ& b) {
	BIO_RAII bio1{ BIO_new(BIO_s_mem()) };
	BIO_RAII bio2{ BIO_new(BIO_s_mem()) };

	if (!bio1 || !bio2) {
		return false;
	}

	if (PEM_write_bio_X509_REQ(bio1.get(), &a) == 0) {
		// Unable to write PEM form, so mark as inequal.
		return false;
	}

	if (PEM_write_bio_X509_REQ(bio2.get(), &b) == 0) {
		// Unable to write PEM form, so mark as inequal.
		return false;
	}

	char* data1 = nullptr;
	const auto bio1Size = BIO_get_mem_data(bio1.get(), &data1);
	char* data2 = nullptr;
	const auto bio2Size = BIO_get_mem_data(bio2.get(), &data2);

	if (bio1Size != bio2Size) {
		return false;
	}

	return memcmp(data1, data2, bio1Size) == 0;
}
