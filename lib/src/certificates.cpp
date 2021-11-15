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

std::optional<Certificate> CertificateManager::getCertificate(const NodeID nodeID) const {
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

	Certificate certificate{ nodeID, nullptr };
	d2i_X509(&certificate.x509, &bytePointer, nodeCertificateBytes.size());

	return certificate;
}

void CertificateManager::setCertificate(const NodeID nodeID, const Certificate certificate) {
	// Create certificate folder if it doesn't exist
	if (!std::filesystem::exists(certificatesFolder)) {
		std::filesystem::create_directory(certificatesFolder);
	}

	unsigned char* certificateBytes = nullptr;
	const int certificateBytesCount = i2d_X509(certificate.x509, &certificateBytes);
	ScopeExit scopeExit1{ [certificateBytes]() { free(certificateBytes); } };

	std::ofstream certificateFile{ getCertificatePath(nodeID) };
	certificateFile.write(reinterpret_cast<char*>(certificateBytes), certificateBytesCount);

	certificatesMap.try_emplace(nodeID, certificate);
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