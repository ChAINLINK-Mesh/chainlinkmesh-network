#include <certificates.hpp>

void instantiate_certificate_manager();
void generate_certificate_request();

void test() {
	instantiate_certificate_manager();
	generate_certificate_request();
}

void instantiate_certificate_manager() {
	[[gnu::unused]] const auto certificateManager =
	    CertificateManager::create_instance(std::filesystem::path{ "/" });
}

void generate_certificate_request() {
	[[gnu::unused]] const auto certificateRequest =
	    CertificateManager::generate_certificate_request({
	        .certificateKeyLength = 2048,
	        .country = "US",
	        .province = "California",
	        .city = "San Francisco",
	        .organisation = "Mozilla",
	        .commonName = "www.mozilla.org",
	        .validityDuration = 60ULL * 60ULL * 24ULL * 365ULL * 10ULL,
	    });
}
