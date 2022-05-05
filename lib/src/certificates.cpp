#include "certificates.hpp"
#include "debug.hpp"
#include "types.hpp"
#include "utilities.hpp"

#include <cassert>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <vector>

extern "C" {
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
}

template <std::integral Encoding>
[[nodiscard]] std::optional<EVP_PKEY_RAII>
GenericCertificateManager<Encoding>::generate_rsa_key() {
	const EVP_PKEY_CTX_RAII rsaCtx{ EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr) };

	// If we failed to generate a valid RSA context.
	if (!rsaCtx) {
		return std::nullopt;
	}

	if (EVP_PKEY_keygen_init(rsaCtx.get()) != 1) {
		return std::nullopt;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(rsaCtx.get(),
	                                     static_cast<int>(KEY_LENGTH)) <= 0) {
		return std::nullopt;
	}

	EVP_PKEY* tempRSAKey = nullptr;
	if (EVP_PKEY_keygen(rsaCtx.get(), &tempRSAKey) != 1) {
		return std::nullopt;
	}

	return EVP_PKEY_RAII{ tempRSAKey };
}

template <std::integral Encoding>
[[nodiscard]] std::optional<X509_RAII>
GenericCertificateManager<Encoding>::generate_certificate(
    const CertificateInfo& certificateInfo, const EVP_PKEY_RAII& rsaKey) {
	assert(certificateInfo.validityDuration < std::numeric_limits<long>::max());

	if (debug_check(static_cast<int>(KEY_LENGTH) !=
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

template <std::integral Encoding>
[[nodiscard]] std::optional<X509_REQ_RAII>
GenericCertificateManager<Encoding>::generate_certificate_request(
    const CertificateInfo& certificateInfo) {
	assert(certificateInfo.validityDuration < std::numeric_limits<long>::max());

	// Generate RSA key
	const auto rsaKey = generate_rsa_key();

	if (!rsaKey) {
		return std::nullopt;
	}

	X509_REQ_RAII x509Req{ X509_REQ_new() };

	// If we failed to initialise the X509 request representation.
	if (!x509Req) {
		return std::nullopt;
	}

	if (X509_REQ_set_version(
	        x509Req.get(),
	        GenericCertificateManager::DEFAULT_CERTIFICATE_VERSION) != 1) {
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

template <std::integral Encoding>
std::optional<X509_RAII>
GenericCertificateManager<Encoding>::decode_pem_certificate(
    const EncodingStringView pem) {
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

	if (certificate == nullptr) {
		return std::nullopt;
	}

	return certificate;
}

template <std::integral Encoding>
std::optional<X509_REQ_RAII>
GenericCertificateManager<Encoding>::decode_pem_csr(EncodingStringView pem) {
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

	if (certificate == nullptr) {
		return std::nullopt;
	}

	return certificate;
}

template <std::integral Encoding>
std::optional<EVP_PKEY_RAII>
GenericCertificateManager<Encoding>::decode_pem_private_key(
    EncodingStringView pem) {
	assert(pem.size() < std::numeric_limits<int>::max());

	BIO_RAII pemBIO{ BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())) };

	if (pemBIO == nullptr) {
		return std::nullopt;
	}

	EVP_PKEY_RAII key{ PEM_read_bio_PrivateKey(pemBIO.get(), nullptr, nullptr,
		                                         nullptr) };

	if (key == nullptr) {
		return std::nullopt;
	}

	return key;
}

template <std::integral Encoding>
std::optional<EVP_PKEY_RAII>
GenericCertificateManager<Encoding>::decode_pem_public_key(
    EncodingStringView pem) {
	assert(pem.size() < std::numeric_limits<int>::max());

	BIO_RAII pemBIO{ BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())) };

	if (pemBIO == nullptr) {
		return std::nullopt;
	}

	EVP_PKEY_RAII key{ PEM_read_bio_PUBKEY(pemBIO.get(), nullptr, nullptr,
		                                     nullptr) };

	if (key == nullptr) {
		return std::nullopt;
	}

	return key;
}

template <std::integral Encoding>
std::optional<std::vector<X509_RAII>>
GenericCertificateManager<Encoding>::decode_pem_certificate_chain(
    EncodingStringView pem) {
	assert(pem.size() < std::numeric_limits<int>::max());

	BIO_RAII pemBIO{ BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())) };

	if (!pemBIO) {
		return std::nullopt;
	}

	std::vector<X509_RAII> certificates{};
	X509_RAII certificate{ PEM_read_bio_X509(pemBIO.get(), nullptr, nullptr,
		                                       nullptr) };

	while (certificate != nullptr) {
		certificates.push_back(std::move(certificate));

		certificate = PEM_read_bio_X509(pemBIO.get(), nullptr, nullptr, nullptr);
	}

	if (certificates.empty()) {
		return std::nullopt;
	}

	return certificates;
}

template <std::integral Encoding>
std::vector<std::string>
GenericCertificateManager<Encoding>::get_subject_attribute(
    const X509_NAME* const subject, const int nid) {
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

template <std::integral Encoding>
std::optional<EVP_PKEY_RAII>
GenericCertificateManager<Encoding>::get_certificate_pubkey(
    const X509_RAII& certificate) {
	assert(certificate != nullptr);

	EVP_PKEY_RAII pubkey{ X509_get_pubkey(certificate.get()) };

	if (pubkey == nullptr) {
		return std::nullopt;
	}

	return pubkey;
}

template <std::integral Encoding>
typename GenericCertificateManager<Encoding>::EncodingString
GenericCertificateManager<Encoding>::encode_pem(const X509_RAII& x509) {
	assert(x509 != nullptr);

	BIO_RAII bio{ BIO_new(BIO_s_mem()) };

	if (PEM_write_bio_X509(bio.get(), x509.get()) == 0) {
		throw std::invalid_argument{ "PEM encoding failure" };
	}

	char* data = nullptr;
	const auto pemSize = BIO_get_mem_data(bio.get(), &data);

	if (pemSize <= 0) {
		throw std::runtime_error{ "PEM buffer read error" };
	}

	return EncodingString{ data, data + pemSize };
}

template <std::integral Encoding>
typename GenericCertificateManager<Encoding>::EncodingString
GenericCertificateManager<Encoding>::encode_pem(const X509_REQ_RAII& x509Req) {
	BIO_RAII bio{ BIO_new(BIO_s_mem()) };

	if (PEM_write_bio_X509_REQ(bio.get(), x509Req.get()) == 0) {
		throw std::invalid_argument{ "PEM encoding failure" };
	}

	char* data = nullptr;
	const auto pemSize = BIO_get_mem_data(bio.get(), &data);

	if (pemSize <= 0) {
		throw std::runtime_error{ "PEM buffer read error" };
	}

	return EncodingString{ data, data + pemSize };
}

template <std::integral Encoding>
typename GenericCertificateManager<Encoding>::EncodingString
GenericCertificateManager<Encoding>::encode_pem(
    const std::vector<X509_RAII>& certificateChain) {
	EncodingString encoding{};

	for (const auto& certificate : certificateChain) {
		encoding += encode_pem(certificate);
	}

	return encoding;
}

template <std::integral Encoding>
typename GenericCertificateManager<Encoding>::EncodingString
GenericCertificateManager<Encoding>::encode_pem(const EVP_PKEY_RAII& pkey) {
	BIO_RAII bio{ BIO_new(BIO_s_mem()) };

	// If this key contains a private key, encode the private key.
	if (PEM_write_bio_PrivateKey(bio.get(), pkey.get(), nullptr, nullptr, 0,
	                             nullptr, nullptr) == 0) {
		// Otherwise, encode the public key it contains.
		if (PEM_write_bio_PUBKEY(bio.get(), pkey.get()) == 0) {
			throw std::invalid_argument{ "PEM encoding failure" };
		}
	}

	char* data = nullptr;
	const auto pemSize = BIO_get_mem_data(bio.get(), &data);

	if (pemSize <= 0) {
		throw std::runtime_error{ "PEM buffer read error" };
	}

	return EncodingString{ data, data + pemSize };
}

template <std::integral Encoding>
std::optional<X509_RAII> GenericCertificateManager<Encoding>::sign_csr(
    X509_REQ_RAII& req, const X509_RAII& caCert, const EVP_PKEY_RAII& key,
    const std::uint64_t validityDurationSeconds) {
	assert(validityDurationSeconds < std::numeric_limits<long>::max());

	X509_RAII signedReq{ X509_new() };

	if (!signedReq) {
		return std::nullopt;
	}

	X509_set_version(signedReq.get(),
	                 GenericCertificateManager::DEFAULT_CERTIFICATE_VERSION);
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

template <std::integral Encoding>
bool GenericCertificateManager<Encoding>::x509_set_name_from_certificate_info(
    X509_NAME* x509Name, const CertificateInfo& certificateInfo) {
	assert(certificateInfo.country.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.province.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.city.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.organisation.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.commonName.size() < std::numeric_limits<int>::max());
	assert(certificateInfo.userID.size() < std::numeric_limits<int>::max());

	// TODO: Replace the string codes with their enumerated versions.
	// Also, "C" is likely to fail, due to the upper-bounds placed on the data
	// length. See: https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1 '--
	// Upper Bounds'
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

	if (X509_NAME_add_entry_by_NID(
	        x509Name, NID_userId, MBSTRING_UTF8,
	        reinterpret_cast<const unsigned char*>(certificateInfo.userID.data()),
	        static_cast<int>(certificateInfo.userID.length()), -1, 0) != 1) {
		return false;
	}

	return true;
}

template class GenericCertificateManager<char>;
template class GenericCertificateManager<unsigned char>;

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

bool operator==(const X509& a, const X509& b) {
	BIO_RAII bio1{ BIO_new(BIO_s_mem()) };
	BIO_RAII bio2{ BIO_new(BIO_s_mem()) };

	if (!bio1 || !bio2) {
		return false;
	}

	if (PEM_write_bio_X509(bio1.get(), &a) == 0) {
		// Unable to write PEM form, so mark as inequal.
		return false;
	}

	if (PEM_write_bio_X509(bio2.get(), &b) == 0) {
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
