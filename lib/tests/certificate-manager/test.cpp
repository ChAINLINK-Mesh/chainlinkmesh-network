#include <certificates.hpp>

void instantiate_certificate_manager();

void test() {
	instantiate_certificate_manager();
}

void instantiate_certificate_manager() {
	[[gnu::unused]] const auto certificateManager =
	    CertificateManager::createInstance(std::filesystem::path{ "/" });
}