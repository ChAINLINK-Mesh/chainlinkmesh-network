#include <certificates.hpp>
#include <test.hpp>
#include <literals.hpp>

void instantiate_certificate_manager();
void generate_certificate_request();
void decode_pem_csr();
void reencode_pem_csr();

void test() {
	instantiate_certificate_manager();
	generate_certificate_request();
	decode_pem_csr();
	reencode_pem_csr();
}

void instantiate_certificate_manager() {
	const auto certificateManager =
	    CertificateManager::create_instance(std::filesystem::path{ "/" });

	if (!certificateManager) {
		throw "Failed to create certificate manager object";
	}
}

void generate_certificate_request() {
	const auto certificateRequest =
	    CertificateManager::generate_certificate_request({
	        .certificateKeyLength = 2048,
	        .country = "US",
	        .province = "California",
	        .city = "San Francisco",
	        .organisation = "Mozilla",
	        .commonName = "www.mozilla.org",
	        .validityDuration = 60ULL * 60ULL * 24ULL * 365ULL * 10ULL,
	    });

	if (!certificateRequest) {
		throw "Failed to generate a valid certificate request";
	}
}

void decode_pem_csr() {
	const auto invalidCSRFile = read_file("private-key.key");

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

void reencode_pem_csr() {
	const auto originalEncoding = read_file("x509-csr.pem");
	const auto decoded =
	    CertificateManager::decode_pem_csr(originalEncoding).value();
	const auto reencoded = CertificateManager::encode_pem(decoded);

	if (originalEncoding != reencoded) {
		throw "Failed to reencode CSR to PEM correctly";
	}
}
