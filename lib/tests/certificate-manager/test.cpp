#include <certificates.hpp>

void instantiate_certificate_manager();
void generate_certificate_request();

void test() {
	instantiate_certificate_manager();
	generate_certificate_request();
}

void instantiate_certificate_manager() {
	[[gnu::unused]] const auto certificateManager =
	    CertificateManager::createInstance(std::filesystem::path{ "/" });
}

void generate_certificate_request() {
	[[gnu::unused]] const auto certificateRequest = CertificateManager::generateCertificateRequest({
	    .certificateKeyLength = 2048,
	    .country = "US",
	    .province = "California",
	    .city = "San Francisco",
	    .organisation = "Mozilla",
	    .commonName = "www.mozilla.org",
	    .validityDuration = 60 * 60 * 24 * 365 * 10,
	});
}