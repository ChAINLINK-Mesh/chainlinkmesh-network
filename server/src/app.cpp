#include "app.hpp"
#include "Poco/Util/Application.h"
#include "certificates.hpp"

#include <Poco/Util/HelpFormatter.h>
#include <Poco/Util/ServerApplication.h>
#include <iostream>
#include <literals.hpp>
#include <memory>

void ServerDaemon::defineOptions(Poco::Util::OptionSet& options) {
	using Poco::Util::Option;
	using Poco::Util::OptionCallback;

	Poco::Util::ServerApplication::defineOptions(options);
	options.addOption(Option{ "help", "h", "this help page" }
	                      .required(false)
	                      .repeatable(false)
	                      .callback(OptionCallback<ServerDaemon>{
	                          this, &ServerDaemon::handle_help }));
	options.addOption(Option{ "server", "s", "setup node as a root server" }
	                      .required(false)
	                      .repeatable(false));
	options.addOption(Option{ "control-plane-keylen", "",
	                          "the length of ChAINLINK RSA key to use" }
	                      .required(false)
	                      .repeatable(false)
	                      .argument("keylength", true));
	options.addOption(
	    Option{ "country", "",
	            "which country the certificate should use (ISO 3166-1 alpha-2)" }
	        .required(false)
	        .repeatable(false)
	        .argument("cn", true));
	options.addOption(
	    Option{ "province", "", "which province the certificate should use" }
	        .required(false)
	        .repeatable(false)
	        .argument("pn", true));
	options.addOption(
	    Option{ "city", "", "which city the certificate should use" }
	        .required(false)
	        .repeatable(false)
	        .argument("ct", true));
	options.addOption(Option{ "organisation", "",
	                          "which organisation the certificate should use" }
	                      .required(false)
	                      .repeatable(false)
	                      .argument("org", true));
	options.addOption(Option{ "common-name", "",
	                          "which common-name the certificate should use" }
	                      .required(false)
	                      .repeatable(false)
	                      .argument("co", true));
	options.addOption(
	    Option{ "validity-duration", "",
	            "how many seconds the CA certificate should be valid for" }
	        .required(false)
	        .repeatable(false)
	        .argument("vs", true));
}

void ServerDaemon::initialize(Poco::Util::Application& self) {
	Poco::Util::ServerApplication::initialize(self);

	X509_RAII certificate{};

	if (config().hasOption("server")) {
		// Generate RSA key
		auto rsaKey = CertificateManager::generate_rsa_key(
		    config().getUInt("keylength", DEFAULT_CERT_INFO.certificateKeyLength));

		if (!rsaKey) {
			std::cerr << "Failed to generate server CA key\n";
		}

		if (auto tempCertificate = CertificateManager::generate_certificate(
		        CertificateInfo{
		            .certificateKeyLength = config().getUInt(
		                "keylength", DEFAULT_CERT_INFO.certificateKeyLength),
		            .country = config().getString(
		                "cn", std::string{ DEFAULT_CERT_INFO.country }),
		            .province = config().getString(
		                "pn", std::string{ DEFAULT_CERT_INFO.province }),
		            .city = config().getString(
		                "ct", std::string{ DEFAULT_CERT_INFO.city }),
		            .organisation = config().getString(
		                "org", std::string{ DEFAULT_CERT_INFO.organisation }),
		            .commonName = config().getString(
		                "co", std::string{ DEFAULT_CERT_INFO.commonName }),
		            .validityDuration = config().getUInt64(
		                "vs", DEFAULT_CERT_INFO.validityDuration),
		        },
		        rsaKey.value())) {
			certificate = std::move(tempCertificate.value());
		} else {
			std::cerr << "Failed to generate server CA certificate\n";
			return;
		}
	}

	// TODO: If not a root certificate, issue an initialisation request to
	// requested server. Use HTTPS / DNS to verify response.

	server = std::make_unique<Server>(
	    Server::Configuration{
	        .id = std::nullopt,
	        .controlPlanePublicKey = ""_uc,
	        .meshPublicKey = {},
	        .wireGuardAddress =
	            Poco::Net::SocketAddress{ "0.0.0.0", DEFAULT_WIREGUARD_PORT },
	        .publicProtoAddress = std::nullopt,
	        .privateProtoAddress = std::nullopt,
	        .controlPlaneCertificate = certificate },
	    EVP_PKEY_RAII{ EVP_PKEY_new() });
}

int ServerDaemon::main(const std::vector<std::string>& args) {
	server->start();
	waitForTerminationRequest();
	return EXIT_OK;
}

void ServerDaemon::display_help() const {
	Poco::Util::HelpFormatter helpFormatter{ options() };
	helpFormatter.setCommand(commandName());
	helpFormatter.setUsage("OPTIONS");
	helpFormatter.setHeader("ChAINLINK - a WireGuard mesh program");
	helpFormatter.format(std::cerr);
}

void ServerDaemon::handle_help(const std::string& /*unused*/,
                               const std::string& /*unused*/) {
	display_help();
	stopOptionsProcessing();
	terminate();
}
