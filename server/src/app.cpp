#include "app.hpp"
#include "certificates.hpp"
#include "clock.hpp"
#include "linux-wireguard-manager.hpp"
#include "literals.hpp"
#include "public-protocol.hpp"
#include "server.hpp"
#include "types.hpp"
#include "utilities.hpp"
#include "validators.hpp"
#include "wireguard.hpp"

#include <Poco/Exception.h>
#include <Poco/Net/IPAddress.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/SocketAddress.h>
#include <Poco/Net/StreamSocket.h>
#include <Poco/Util/Application.h>
#include <Poco/Util/HelpFormatter.h>
#include <Poco/Util/IntValidator.h>
#include <Poco/Util/OptionException.h>
#include <Poco/Util/ServerApplication.h>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <variant>

const constexpr std::string_view SERVER_IP_PLACEHOLDER = "SERVER_IP_HERE";
const constexpr std::string_view SERVER_CONFIG_FILE = "/tmp/chainlink.conf";

void ServerDaemon::defineOptions(Poco::Util::OptionSet& options) {
	using Poco::Util::Option;
	using Poco::Util::OptionCallback;

	Poco::Util::ServerApplication::defineOptions(options);

	options.addOption(Option{ "help", "h", "this help page" }
	                      .required(false)
	                      .repeatable(false)
	                      .callback(OptionCallback<ServerDaemon>{
	                          this, &ServerDaemon::handle_help }));
	options.addOption(Option{ "client", "c", "setup node to connect to a parent" }
	                      .required(false)
	                      .repeatable(false)
	                      .argument("parent", true)
	                      .binding("parent")
	                      .callback(handle_flag())
	                      .group("run-mode"));
	// TODO: Create a uint64_t validator, and use here.
	options.addOption(
	    Option{ "referrer", "", "which node offerred an invitation" }
	        .required(false)
	        .repeatable(false)
	        .argument("ID")
	        .binding("referrer"));
	options.addOption(Option{ "timestamp", "", "timestamp of invitation" }
	                      .required(false)
	                      .repeatable(false)
	                      .argument("UTC")
	                      .binding("timestamp"));
	options.addOption(Option{ "psk-hash", "", "SHA256 hash of timestamp and PSK" }
	                      .required(false)
	                      .repeatable(false)
	                      .argument("SHA256")
	                      .binding("pskHash"));
	options.addOption(Option{ "psk-signature", "", "signature of PSK" }
	                      .required(false)
	                      .repeatable(false)
	                      .argument("signature")
	                      .binding("signature"));
	options.addOption(Option{ "server", "s", "setup node as a root server" }
	                      .required(false)
	                      .repeatable(false)
	                      .group("run-mode")
	                      .binding("server")
	                      .callback(handle_flag()));
	options.addOption(
	    Option{ "country", "",
	            "which country the certificate should use (ISO 3166-1 alpha-2)" }
	        .required(false)
	        .repeatable(false)
	        .argument("cn", true)
	        .binding("country"));
	options.addOption(
	    Option{ "province", "", "which province the certificate should use" }
	        .required(false)
	        .repeatable(false)
	        .argument("pn", true)
	        .binding("province"));
	options.addOption(
	    Option{ "city", "", "which city the certificate should use" }
	        .required(false)
	        .repeatable(false)
	        .argument("ct", true)
	        .binding("city"));
	options.addOption(Option{ "organisation", "",
	                          "which organisation the certificate should use" }
	                      .required(false)
	                      .repeatable(false)
	                      .argument("org", true)
	                      .binding("organisation"));
	options.addOption(Option{ "common-name", "",
	                          "which common-name the certificate should use" }
	                      .required(false)
	                      .repeatable(false)
	                      .argument("co", true)
	                      .binding("common-name"));
	options.addOption(
	    Option{ "validity-duration", "",
	            "how many seconds the CA certificate should be valid for" }
	        .required(false)
	        .repeatable(false)
	        .argument("vs", true)
	        .binding("validity-duration")
	        .validator(
	            new Poco::Util::IntValidator{ MIN_VALIDITY, MAX_VALIDITY }));
	options.addOption(
	    Option{ "public-address", "",
	            "the IP:Port pair to listen on for public control-plane traffic" }
	        .required(false)
	        .repeatable(false)
	        .argument("addr")
	        .binding("public-address"));
	options.addOption(
	    Option{ "psk", "p", "the pre-shared-key to use to authenticate" }
	        .required(false)
	        .repeatable(false)
	        .argument("password")
	        .binding("psk"));
	options.addOption(
	    Option{ "psk-ttl", "", "the time a pre-shared-key should be valid for" }
	        .required(false)
	        .repeatable(false)
	        .argument("ttl")
	        .binding("psk-ttl"));
	options.addOption(
	    Option{ "wireguard-address", "",
	            "the IP:Port pair to listen on for WireGuard traffic. Should be "
	            "publicly accessible if other nodes need to "
	            "connect to it" }
	        .required(false)
	        .repeatable(false)
	        .argument("addr")
	        .binding("wireguard-address"));
}

void ServerDaemon::initialize(Poco::Util::Application& self) {
	Poco::Util::ServerApplication::initialize(self);

	if (shouldExit) {
		return;
	}

	X509_RAII certificate{};

	std::optional<ByteString> psk{};

	if (config().hasOption("psk")) {
		const auto pskString = config().getString("psk");
		std::cerr << "Using PSK: " << pskString << "\n";
		psk = ByteString{ pskString.begin(), pskString.end() };
	}

	AbstractWireGuardManager::Key wgPrivateKey;
	AbstractWireGuardManager::Key wgPublicKey;
	{
		wg_key tempWGPrivateKey;
		wg_generate_private_key(tempWGPrivateKey);
		std::copy(std::begin(tempWGPrivateKey), std::end(tempWGPrivateKey),
		          wgPrivateKey.begin());
		wg_key tempWGPublicKey;
		wg_generate_public_key(tempWGPublicKey, tempWGPrivateKey);
		std::copy(std::begin(tempWGPublicKey), std::end(tempWGPublicKey),
		          wgPublicKey.begin());
	}
	const auto userID = base64_encode(
	    std::span<const std::uint8_t>{ wgPublicKey.data(), wgPublicKey.size() });

	if (!userID) {
		logger().fatal("Failed to encode WireGuard key for certificate\n");
		return;
	}

	std::vector<Node> peers{};
	std::optional<std::uint64_t> id{};
	std::optional<std::uint64_t> parent{};

	Poco::AutoPtr<Poco::Util::PropertyFileConfiguration> savedConfig{};

	try {
		savedConfig = new Poco::Util::PropertyFileConfiguration{ std::string{
			  SERVER_CONFIG_FILE } };
	} catch (const Poco::FileNotFoundException& e) {
		// Ignore failure to open config. This just indicates we have to parse the
		// commandline flags instead.
	}

	std::optional<Server::Configuration> configuration{};

	if (!savedConfig.isNull() && savedConfig->has("id")) {
		logger().notice("Using saved configuration");

		const auto decodedConfiguration =
		    Server::get_configuration_from_saved_config(savedConfig);

		if (std::holds_alternative<Server::Configuration>(decodedConfiguration)) {
			configuration = std::get<Server::Configuration>(decodedConfiguration);
		} else {
			try {
				std::rethrow_exception(
				    std::get<std::exception_ptr>(decodedConfiguration));
			} catch (const std::exception& e) {
				logger().fatal(
				    std::string{ "Failed to decode existing configuration: " } +
				    e.what());
				return;
			}
		}
	} else {
		if (config().hasOption("server") || !config().hasOption("client")) {
			logger().notice("Running in root CA mode");

			// Generate RSA key
			auto rsaKey = CertificateManager::generate_rsa_key();

			if (!rsaKey) {
				logger().fatal("Failed to generate server CA key\n");
				return;
			}

			if (auto tempCertificate = CertificateManager::generate_certificate(
			        CertificateInfo{
			            .country = config().getString(
			                "country", std::string{ DEFAULT_CERT_INFO.country }),
			            .province = config().getString(
			                "province", std::string{ DEFAULT_CERT_INFO.province }),
			            .city = config().getString(
			                "city", std::string{ DEFAULT_CERT_INFO.city }),
			            .organisation = config().getString(
			                "organisation",
			                std::string{ DEFAULT_CERT_INFO.organisation }),
			            .commonName = config().getString(
			                "common-name",
			                std::string{ DEFAULT_CERT_INFO.commonName }),
			            .userID = userID.value(),
			            .validityDuration = config().getUInt64(
			                "validity-duration", DEFAULT_CERT_INFO.validityDuration),
			        },
			        rsaKey.value())) {
				certificate = std::move(tempCertificate.value());
			} else {
				logger().fatal("Failed to generate server CA certificate\n");
				return;
			}
		} else {
			logger().notice("Running in client mode");

			auto parentAddressStr = config().getString("parent");

			if (parentAddressStr.empty()) {
				logger().fatal("Cannot connect to blank parent\n");
				return;
			}

			// If the user has failed to replace the placeholder parameter from the
			// invite.
			if (parentAddressStr.starts_with(SERVER_IP_PLACEHOLDER)) {
				std::cerr << "IP address of parent: ";
				std::string parentIP{};
				std::cin >> parentIP;
				parentAddressStr.replace(0, SERVER_IP_PLACEHOLDER.length(), parentIP);
			}

			std::uint64_t referringNode{};

			try {
				referringNode = config().getUInt64("referrer");
			} catch (const Poco::Util::OptionException& e) {
				logger().fatal("Couldn't parse referrer (should be an integer)\n");
				return;
			}

			CertificateInfo certInfo{
				.country = config().getString("country",
				                              std::string{ DEFAULT_CERT_INFO.country }),
				.province = config().getString(
				    "province", std::string{ DEFAULT_CERT_INFO.province }),
				.city =
				    config().getString("city", std::string{ DEFAULT_CERT_INFO.city }),
				.organisation = config().getString(
				    "organisation", std::string{ DEFAULT_CERT_INFO.organisation }),
				.commonName = config().getString(
				    "common-name", std::string{ DEFAULT_CERT_INFO.commonName }),
				.userID = userID.value(),
				.validityDuration = config().getUInt64(
				    "validity-duration", DEFAULT_CERT_INFO.validityDuration),
			};

			// TODO: Replace with parameterised clock.
			const std::uint64_t timestamp = config().getUInt64(
			    "timestamp", std::chrono::time_point_cast<std::chrono::seconds>(
			                     SystemClock{}.now())
			                     .time_since_epoch()
			                     .count());

			const auto pskHashStr = base64_decode(config().getString("pskHash"));
			assert(pskHashStr);
			PublicProtocol::InitialisationPacket::Hash pskHash{};
			std::copy(pskHashStr->begin(), pskHashStr->end(), pskHash.begin());

			const auto pskSignatureStr =
			    base64_decode(config().getString("signature"));
			assert(pskSignatureStr);
			PublicProtocol::InitialisationPacket::Signature pskSignature{};
			std::copy(pskSignatureStr->begin(), pskSignatureStr->end(),
			          pskSignature.begin());

			PublicProtocol::PublicProtocolClient client{
				PublicProtocol::PublicProtocolClient::Configuration{
				    .certInfo = certInfo,
				    .parentAddress = Host{ parentAddressStr },
				    .pskHash = pskHash,
				    .pskSignature = pskSignature,
				    .referringNode = referringNode,
				    .timestamp = timestamp,
				}
			};

			try {
				const auto resp = client.connect();
				// TODO: Decode the control-plane pubkey from certificate.
				peers.push_back(Node{
				    .id = resp.respondingNode,
				    .controlPlanePublicKey = {},
				    .wireGuardPublicKey = resp.respondingWireGuardPublicKey,
				    .controlPlaneIP = resp.respondingControlPlaneIPAddress,
				    .controlPlanePort = resp.respondingControlPlanePort,
				    .wireGuardHost = client.get_parent_address(resp),
				    .wireGuardPort = resp.respondingWireGuardPort,
				    .controlPlaneCertificate = {},
				});
				id = resp.allocatedNode;
				parent = resp.respondingNode;
			} catch (const std::invalid_argument& e) {
				logger().fatal(std::string{ "Invalid argument: " } + e.what() + "\n");
				return;
			} catch (const std::runtime_error& e) {
				logger().fatal(std::string{ "Error: " } + e.what() + "\n");
				return;
			}
		}

		// TODO: load private key
		const auto privateKey{ CertificateManager::generate_rsa_key() };

		if (!privateKey) {
			logger().fatal("Failed to generate private key\n");
			return;
		}

		std::optional<Poco::Net::SocketAddress> publicAddress{};

		if (config().hasOption("public-address")) {
			const auto controlPlaneAddressStr = config().getString("public-address");
			std::cerr << "Using address: " << controlPlaneAddressStr << "\n";

			try {
				publicAddress = Poco::Net::SocketAddress{ controlPlaneAddressStr };
			} catch (const Poco::Net::InvalidAddressException& e) {
				logger().fatal("Failed to decode the address '" +
				               controlPlaneAddressStr + "'\n");
				return;
			}
		}

		const auto pskTTL = config().getUInt64(
		    "psk-ttl", PublicProtocol::PublicProtocolManager::DEFAULT_PSK_TTL);
		psk = psk.value_or(PublicProtocol::PublicProtocolManager::DEFAULT_PSK);

		configuration = Server::Configuration{
			.id = id,
			.parent = parent,
			.controlPlanePrivateKey = privateKey.value(),
			.meshPublicKey = wgPublicKey,
			.meshPrivateKey = wgPrivateKey,
			.wireGuardAddress = Poco::Net::SocketAddress{ config().getString(
			    "wireguard-address",
			    "0.0.0.0:" + std::to_string(Node::DEFAULT_WIREGUARD_PORT)) },
			.publicProtoAddress = publicAddress,
			.privateProtoPort = std::nullopt,
			.controlPlaneCertificate = certificate,
			.psk = psk.value(),
			.pskTTL = pskTTL,
			.peers = peers,
		};
	}

	assert(configuration);

	server = std::make_unique<Server>(configuration.value());

	// If running in root CA mode
	if (config().hasOption("server") || !config().hasOption("client")) {
		const auto serverNode = server->get_self();
		logger().information("Root server has ID: " +
		                     std::to_string(serverNode.id));
		const auto optSignedPSK = server->get_signed_psk();
		assert(optSignedPSK);
		const auto [timestamp, pskHash, pskSignature] = optSignedPSK.value();
		logger().information("Connect using: \n");
		const auto b64EncodedHash = base64_encode(pskHash);
		assert(b64EncodedHash);
		const auto b64EncodedSignature = base64_encode(pskSignature);
		assert(b64EncodedSignature);
		logger().information("\tTimestamp: " + std::to_string(timestamp));
		logger().information("\tPSK Hash: " + b64EncodedHash.value());
		logger().information("\tPSK Signature: " + b64EncodedSignature.value() +
		                     "\n");
		logger().information(
		    "I.e.: docker run --network=host --cap-add=NET_ADMIN -it "
		    "michaelkuc6/wgmesh-server wgmesh-server"
		    " \\\n\t--timestamp=" +
		    std::to_string(timestamp) +
		    " \\\n\t--psk-hash=" + b64EncodedHash.value() +
		    " \\\n\t--psk-signature=" + b64EncodedSignature.value() +
		    " \\\n\t--psk-ttl=" + std::to_string(serverNode.pskTTL) +
		    " \\\n\t--referrer=" + std::to_string(serverNode.id) +
		    " \\\n\t--client=" + std::string{ SERVER_IP_PLACEHOLDER } + ":" +
		    std::to_string(server->get_public_proto_address().port()) + "\n");
	}
}

int ServerDaemon::main(const std::vector<std::string>& args) {
	if (!server) {
		return EXIT_FAILURE;
	}

	server->start();
	waitForTerminationRequest();
	server->stop();

	// TODO: Install failure handler to set the interface back down.
	get_configuration()->save(std::string{ SERVER_CONFIG_FILE });

	return EXIT_OK;
}

Poco::AutoPtr<Poco::Util::PropertyFileConfiguration>
ServerDaemon::get_configuration() const {
	return server->get_configuration();
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
	shouldExit = true;
	terminate();
}

void ServerDaemon::handle_flag_impl(const std::string& flag,
                                    const std::string& /*unused*/) {
	config().setBool(flag, true);
}

Poco::Util::OptionCallback<ServerDaemon> ServerDaemon::handle_flag() {
	return Poco::Util::OptionCallback<ServerDaemon>{
		this,
		&ServerDaemon::handle_flag_impl,
	};
}

const CertificateInfo ServerDaemon::DEFAULT_CERT_INFO = {
	.country = "UK",
	.province = "Test Province",
	.city = "Test City",
	.organisation = "Test Organisation",
	.commonName = "Test Common Name",
	.validityDuration = PublicProtocol::PublicProtocolManager::
	    DEFAULT_CERTIFICATE_VALIDITY_SECONDS,
};
