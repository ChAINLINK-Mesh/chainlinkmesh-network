#pragma once

#include <cinttypes>
#include <filesystem>
#include <map>
#include <openssl/x509v3.h>
#include <optional>

using NodeID = std::uint64_t;

struct Certificate {
	NodeID id;
	X509* x509;
};

class CertificateManager {
public:
	std::optional<Certificate> getCertificate(NodeID nodeID) const;
	void setCertificate(NodeID nodeID, Certificate certificate);

	CertificateManager(CertificateManager&& other) = default;
	~CertificateManager() = default;

	static std::shared_ptr<CertificateManager>
	createInstance(const std::filesystem::path certificatesFolder);
	static std::shared_ptr<CertificateManager> getInstance();

protected:
	CertificateManager(const std::filesystem::path certificatesFolder);

	std::filesystem::path getCertificatePath(NodeID nodeID) const;

	const std::filesystem::path certificatesFolder;
	mutable std::map<NodeID, Certificate> certificatesMap;

	static std::shared_ptr<CertificateManager> instance;
};
