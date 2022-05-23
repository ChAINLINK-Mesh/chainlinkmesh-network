#include "test.hpp"
#include "certificates.hpp"
#include "literals.hpp"

#include <limits>

extern "C" {
#include <openssl/evp.h>
}

void generate_rsa_key();
void generate_certificate();
void generate_certificate_request();
void equality_certificate();
void equality_certificate_request();
void decode_pem_csr();
void decode_pem_certificate_chain();
void reencode_pem_csr();
void sign_data();

void test() {
	generate_rsa_key();
	generate_certificate();
	generate_certificate_request();
	equality_certificate();
	equality_certificate_request();
	decode_pem_csr();
	decode_pem_certificate_chain();
	reencode_pem_csr();
	sign_data();
}

void generate_rsa_key() {
	const auto validLengthKey = CertificateManager::generate_rsa_key();

	if (!validLengthKey) {
		throw "Failed to create a valid " +
		    std::to_string(CertificateManager::KEY_LENGTH) + "-bit RSA key";
	}

	if (EVP_PKEY_get_base_id(validLengthKey->get()) != EVP_PKEY_RSA) {
		throw "Failed to generate an RSA key, generated another cryptosystem's key "
		      "instead";
	}

	if (const auto kl = EVP_PKEY_get_bits(validLengthKey->get());
	    kl != CertificateManager::KEY_LENGTH) {
		throw "Created a valid RSA key, but was " + std::to_string(kl) +
		    " bits instead of the requested " +
		    std::to_string(CertificateManager::KEY_LENGTH) + " bits";
	}
}

void generate_certificate() {
	CertificateInfo certificateInfo{
		.country = "GB",
		.province = "England",
		.city = "London",
		.organisation = "Imperial College London",
		.commonName = "imperial.ac.uk",
		.userID = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
		.serialNumber = "123456789",
		.validityDuration = 900,
	};

	if (CertificateManager::generate_certificate(certificateInfo,
	                                             EVP_PKEY_RAII{})) {
		throw "Incorrectly created a certificate from invalid null private key";
	}

	const auto key = CertificateManager::generate_rsa_key().value();
	const CertificateInfo invalidCertificateInfo{
		.country = "",
		.province = "",
		.city = "",
		.organisation = "",
		.commonName = "",
		.userID = "",
		.serialNumber = "",
		.validityDuration = 900,
	};

	if (CertificateManager::generate_certificate(invalidCertificateInfo, key)) {
		throw "Incorrectly created certificate from invalid certificate "
		      "information";
	}

	const auto validCertificate =
	    CertificateManager::generate_certificate(certificateInfo, key);

	if (!validCertificate) {
		throw "Failed to create certificate from valid details.";
	}
}

void generate_certificate_request() {
	const auto certificateRequest =
	    CertificateManager::generate_certificate_request(
	        {
	            .country = "US",
	            .province = "California",
	            .city = "San Francisco",
	            .organisation = "Mozilla",
	            .commonName = "www.mozilla.org",
	            .userID = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
	            .serialNumber = std::nullopt,
	            .validityDuration = 60ULL * 60ULL * 24ULL * 365ULL * 10ULL,
	        },
	        std::nullopt);

	if (!certificateRequest) {
		throw "Failed to generate a valid certificate request";
	}
}

void equality_certificate() {
	const auto key = CertificateManager::generate_rsa_key().value();
	const auto certificate1 = CertificateManager::generate_certificate(
	    {
	        .country = "US",
	        .province = "California",
	        .city = "San Francisco",
	        .organisation = "Mozilla",
	        .commonName = "www.mozilla.org",
	        .userID = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
	        .serialNumber = "123456789",
	        .validityDuration = 60ULL * 60ULL * 24ULL * 365ULL * 10ULL,
	    },
	    key);

	if (*certificate1->get() != *certificate1->get()) {
		throw "Equality check on the same value returned 'inequal'";
	}

	const auto certificate2 = CertificateManager::generate_certificate(
	    CertificateInfo{
	        .country = "UK",
	        .province = "London",
	        .city = "London",
	        .organisation = "Test",
	        .commonName = "test.co.uk",
	        .userID = "XJMrXJMrXJMrXJMrXJMrXJMrXJMrXJMrXJMrXJMrXJU=",
	        .serialNumber = "123456789",
	        .validityDuration = 60ULL * 60ULL * 24ULL * 365ULL * 10ULL,
	    },
	    key);

	if (*certificate1->get() == *certificate2->get()) {
		throw "Equality check on a different value returned 'equal'";
	}
}

void equality_certificate_request() {
	const auto certificateRequest1 =
	    CertificateManager::generate_certificate_request(
	        {
	            .country = "US",
	            .province = "California",
	            .city = "San Francisco",
	            .organisation = "Mozilla",
	            .commonName = "www.mozilla.org",
	            .userID = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
	            .serialNumber = std::nullopt,
	            .validityDuration = 60ULL * 60ULL * 24ULL * 365ULL * 10ULL,
	        },
	        std::nullopt);

	if (certificateRequest1.value() != certificateRequest1.value()) {
		throw "Equality check on the same value returned 'inequal'";
	}

	const auto certificateRequest2 =
	    CertificateManager::generate_certificate_request(
	        CertificateInfo{
	            .country = "UK",
	            .province = "London",
	            .city = "London",
	            .organisation = "Test",
	            .commonName = "test.co.uk",
	            .userID = "XJMrXJMrXJMrXJMrXJMrXJMrXJMrXJMrXJMrXJMrXJU=",
	            .serialNumber = std::nullopt,
	            .validityDuration = 60ULL * 60ULL * 24ULL * 365ULL * 10ULL,
	        },
	        std::nullopt);

	if (certificateRequest1.value() == certificateRequest2.value()) {
		throw "Equality check on a different value returned 'equal'";
	}
}

void decode_pem_csr() {
	const auto invalidCSRFile = read_file("private-key.pem");

	if (const auto invalidCSR =
	        CertificateManager::decode_pem_csr(invalidCSRFile)) {
		throw "Decoded invalid CSR (this is an error)";
	}

	const auto invalidPEMFile = read_file("invalid-csr.data");

	if (const auto invalidPEM =
	        CertificateManager::decode_pem_csr(invalidPEMFile)) {
		throw "Decoded invalid PEM file as CSR (this is an error)";
	}

	const auto* const empty = ""_uc;

	if (const auto emptyPEM = CertificateManager::decode_pem_csr(empty)) {
		throw "Decoded empty file as CSR (this is an error)";
	}

	const auto pemFile = read_file("x509-csr.pem");
	const auto optPEMCSR = CertificateManager::decode_pem_csr(pemFile);

	if (!optPEMCSR) {
		throw "Failed to decode valid PEM CSR";
	}

	auto* const csrSubject = X509_REQ_get_subject_name(optPEMCSR.value().get());
	const auto commonNames =
	    CertificateManager::get_subject_attribute(csrSubject, NID_commonName);

	if (commonNames.size() != 1) {
		throw "Wrong number of common names decoded from CSR";
	}

	if (commonNames[0] != "Common Name") {
		throw "Invalid common name decoded from CSR";
	}

	if (optPEMCSR.value() != optPEMCSR.value()) {
		throw "Failure comparing valid CSR";
	}
}

void decode_pem_certificate_chain() {
	const auto originalEncoding = read_file("x509-chain.pem");
	const auto decoded =
	    CertificateManager::decode_pem_certificate_chain(originalEncoding);

	if (!decoded) {
		throw "Failure to decode certificate chain";
	}

	if (decoded->size() != 2) {
		throw "Decoded certificate chain has wrong number of certificates";
	}

	const auto certificate1 =
	    CertificateManager::decode_pem_certificate(read_file("x509-chain.1.pem"));
	const auto certificate2 =
	    CertificateManager::decode_pem_certificate(read_file("x509-chain.2.pem"));

	if (*decoded->at(0) != *certificate1->get()) {
		throw "First certificate in certificate chain is invalid";
	}

	if (*decoded->at(1) != *certificate2->get()) {
		throw "Second certificate in certificate chain is invalid";
	}
}

void reencode_pem_csr() {
	const auto originalEncoding = read_file("x509-csr.pem");
	const auto decoded =
	    CertificateManager::decode_pem_csr(originalEncoding).value();
	const auto reencoded = CertificateManager::encode_pem(decoded);

	if (originalEncoding != reencoded) {
		throw "Failed to reencode CSR to PEM correctly";
	}
}

void sign_data() {
	const constexpr size_t randDataSize = 1024;
	std::array<std::uint8_t, randDataSize> randData{};

	for (unsigned char& i : randData) {
		i = rand() % std::numeric_limits<std::uint8_t>::max();
	}

	const auto key = CertificateManager::generate_rsa_key();
	assert(key.has_value());
	const auto signature = CertificateManager::sign_data(key.value(), randData);

	if (!signature.has_value()) {
		throw "Failed to sign data";
	}

	const auto signatureMatches = CertificateManager::check_signature(
	    key.value(), randData, signature.value());

	if (!signatureMatches.has_value()) {
		throw "Failed to check if signature is associated to its signing key";
	}

	if (!signatureMatches.value()) {
		throw "Expected signature to match the key which signed it";
	}

	const auto otherKey = CertificateManager::generate_rsa_key();
	assert(otherKey.has_value());

	const auto otherSignatureMatches = CertificateManager::check_signature(
	    otherKey.value(), randData, signature.value());

	if (!otherSignatureMatches.has_value()) {
		throw "Failed to check if signature is associated to a different key";
	}

	if (otherSignatureMatches.value()) {
		throw "Expected signature not to match a different key from the one which "
		      "signed it";
	}
}
