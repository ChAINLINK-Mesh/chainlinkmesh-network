#pragma once

#include "public-protocol.hpp"
#include "server.hpp"
#include <Poco/Util/Application.h>
#include <Poco/Util/OptionSet.h>
#include <Poco/Util/ServerApplication.h>
#include <memory>

class ServerDaemon : public Poco::Util::ServerApplication {
public:
	using Poco::Util::ServerApplication::ServerApplication;

	void defineOptions(Poco::Util::OptionSet& options) override;
	void initialize(Poco::Util::Application& self) override;
	int main(const std::vector<std::string>& args) override;

protected:
	std::unique_ptr<Server> server;

	void display_help() const;
	void handle_help(const std::string&, const std::string&);

	const constexpr static std::uint16_t DEFAULT_WIREGUARD_PORT = 51820;
	const constexpr static CertificateInfo DEFAULT_CERT_INFO = {
		.certificateKeyLength = 2048,
		.country = "UK",
		.province = "Test Province",
		.city = "Test City",
		.organisation = "Test Organisation",
		.commonName = "Test Common Name",
		.validityDuration = PublicProtocol::PublicProtocolManager::
		    DEFAULT_CERTIFICATE_VALIDITY_SECONDS,
	};
};
