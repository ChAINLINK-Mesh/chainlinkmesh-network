#include <certificates.hpp>
#include <test.hpp>

void instantiate_certificate_manager();
void generate_certificate_request();
void decode_pem_csr();

void test() {
	instantiate_certificate_manager();
	generate_certificate_request();
	decode_pem_csr();
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
	const auto invalidPemFile = read_file("private-key.key");
	const auto invalidPemCSR = CertificateManager::decode_pem_csr(invalidPemFile);

	if (invalidPemCSR) {
		throw "Decoded invalid PEM CSR (this is an error)";
	}

	// TODO: Include an invalidly-PEM-formatted file.
	// Above is just a PEM-formatted file which is not a CSR.

	const auto pemFile = read_file("x509-csr.pem");
	const auto pemCSR = CertificateManager::decode_pem_csr(pemFile);

	if (!pemCSR) {
		throw "Failed to decode valid PEM CSR";
	}
}
