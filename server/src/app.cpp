#include "app.hpp"
#include "Poco/Net/IPAddress.h"
#include "Poco/Net/NetException.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Util/IntValidator.h"
#include "Poco/Util/OptionException.h"
#include "certificates.hpp"
#include "clock.hpp"
#include "public-protocol.hpp"
#include "utilities.hpp"
#include "validators.hpp"

#include <Poco/Util/Application.h>
#include <Poco/Util/HelpFormatter.h>
#include <Poco/Util/ServerApplication.h>
#include <chrono>
#include <cstdlib>
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
	    Option{ "keylength", "", "the length of ChAINLINK RSA key to use" }
	        .required(false)
	        .repeatable(false)
	        .argument("length", true)
	        .binding("keylength")
	        .validator(
	            new PowerOfTwoValidator{ MIN_KEY_LENGTH, MAX_KEY_LENGTH }));
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
}

void ServerDaemon::initialize(Poco::Util::Application& self) {
	Poco::Util::ServerApplication::initialize(self);

	X509_RAII certificate{};

	std::optional<std::string> psk{};

	if (config().hasOption("psk")) {
		psk = config().getString("psk");
		std::cerr << "Using PSK: " << psk.value() << "\n";
	}

	if (config().hasOption("server") || !config().hasOption("client")) {
		logger().notice("Running in root CA mode");

		const auto keyLength =
		    config().getUInt("keylength", DEFAULT_CERT_INFO.certificateKeyLength);

		// Generate RSA key
		auto rsaKey = CertificateManager::generate_rsa_key(keyLength);

		if (!rsaKey) {
			logger().fatal("Failed to generate server CA key\n");
			return;
		}

		if (auto tempCertificate = CertificateManager::generate_certificate(
		        CertificateInfo{
		            .certificateKeyLength = keyLength,
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
		                "common-name", std::string{ DEFAULT_CERT_INFO.commonName }),
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

		const auto parentAddressStr = config().getString("parent");

		if (parentAddressStr.empty()) {
			logger().fatal("Cannot connect to blank parent\n");
			return;
		}

		std::optional<Poco::Net::IPAddress> parentAddress{};
		std::optional<std::uint16_t> port;

		const auto tryDecodeIPPortPair =
		    [](const std::string& addr) -> std::optional<Poco::Net::SocketAddress> {
			try {
				return Poco::Net::SocketAddress{ addr };
			} catch (Poco::Net::InvalidAddressException&) {
				return std::nullopt;
			}
		};

		if (const auto decodedAddr = tryDecodeIPPortPair(parentAddressStr)) {
			parentAddress = decodedAddr->host();
			port = decodedAddr->port();
		} else if (Poco::Net::IPAddress ip{};
		           Poco::Net::IPAddress::tryParse(parentAddressStr, ip)) {
			parentAddress = ip;
		}

		if (!parentAddress) {
			logger().fatal("Cannot parse parent address '" + parentAddressStr +
			               "'\n");
			return;
		}

		std::uint64_t referringNode{};

		try {
			referringNode = config().getUInt64("referrer");
		} catch (const Poco::Util::OptionException& e) {
			logger().fatal("Couldn't parse referrer (should be an integer)\n");
			return;
		}

		auto csr = CertificateManager::generate_certificate_request(CertificateInfo{
		    .certificateKeyLength = config().getUInt(
		        "keylength", DEFAULT_CERT_INFO.certificateKeyLength),
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
		    .validityDuration = config().getUInt64(
		        "validity-duration", DEFAULT_CERT_INFO.validityDuration),
		});

		if (!csr) {
			logger().fatal("Couldn't generate certificate signing request\n");
			return;
		}

		// TODO: Replace with parameterised clock.
		const std::uint64_t timestamp = config().getUInt64(
		    "timestamp",
		    std::chrono::time_point_cast<std::chrono::seconds>(SystemClock{}.now())
		        .time_since_epoch()
		        .count());

		const auto pskHashStr = base64_decode(config().getString("pskHash"));
		assert(pskHashStr);
		PublicProtocol::InitialisationPacket::Hash pskHash{};
		std::copy(pskHashStr->begin(), pskHashStr->end(), pskHash.begin());

		const auto pskSignatureStr = base64_decode(config().getString("signature"));
		assert(pskSignatureStr);
		PublicProtocol::InitialisationPacket::Signature pskSignature{};
		std::copy(pskSignatureStr->begin(), pskSignatureStr->end(),
		          pskSignature.begin());

		// Create initialisation packet before connecting to avoid delays actually
		// sending the data.
		const PublicProtocol::InitialisationPacket initPacket{
			.timestamp = timestamp,
			.timestampPSKHash = pskHash,
			.referringNode = referringNode,
			.timestampPSKSignature = pskSignature,
			.csr = std::move(csr.value()),
		};

		Poco::Net::StreamSocket publicSocket{ Poco::Net::SocketAddress(
			  { parentAddress.value(),
			    port.value_or(PublicProtocol::DEFAULT_CONTROL_PLANE_PORT) }) };

		const auto bytes = initPacket.get_bytes();

		assert(bytes.size() < std::numeric_limits<int>::max());
		publicSocket.sendBytes(bytes.data(), static_cast<int>(bytes.size()));
		ByteString responseBytes(
		    PublicProtocol::InitialisationRespPacket::MAX_PACKET_SIZE, '\0');

		assert(responseBytes.size() < std::numeric_limits<int>::max());

		if (publicSocket.receiveBytes(responseBytes.data(),
		                              static_cast<int>(responseBytes.size())) <
		    PublicProtocol::InitialisationRespPacket::MIN_PACKET_SIZE) {
			logger().fatal(
			    "Failed to receive a valid response from the root server\n");
			return;
		}

		const auto response =
		    PublicProtocol::InitialisationRespPacket::decode_bytes(responseBytes);

		if (!response) {
			logger().fatal("Response received from the root server was invalid\n");
		}

		logger().information("I was allocated node: " +
		                     std::to_string(response->allocatedNode));

		// TODO: Lookup DNS addresses.
		// TODO: Issue an initialisation request to requested server.
		// TODO: Use HTTPS / DNS to verify response.
	}

	// TODO: load private key
	const auto privateKey{ CertificateManager::generate_rsa_key(2048) };

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
			logger().fatal("Failed to decode the address '" + controlPlaneAddressStr +
			               "'\n");
			return;
		}
	}

	const auto pskTTL = config().getUInt64(
	    "psk-ttl", PublicProtocol::PublicProtocolManager::DEFAULT_PSK_TTL);

	server = std::make_unique<Server>(Server::Configuration{
	    .id = std::nullopt,
	    .controlPlanePrivateKey = privateKey.value(),
	    .meshPublicKey = {},
	    .wireGuardAddress =
	        Poco::Net::SocketAddress{ "0.0.0.0", DEFAULT_WIREGUARD_PORT },
	    .publicProtoAddress = publicAddress,
	    .privateProtoAddress = std::nullopt,
	    .controlPlaneCertificate = certificate,
	    .psk = config().getString(
	        "psk", PublicProtocol::PublicProtocolManager::DEFAULT_PSK),
	    .pskTTL = pskTTL,
	});

	logger().information("Using PSK: " + server->get_psk() + " (valid for " +
	                     std::to_string(pskTTL) + " seconds)");

	// If running in root CA mode
	if (config().hasOption("server") || !config().hasOption("client")) {
		logger().information("Root server has ID: " +
		                     std::to_string(server->get_self().id));
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
		logger().information("I.e.: --timestamp=" + std::to_string(timestamp) +
		                     " --psk-hash=" + b64EncodedHash.value() +
		                     " --psk-signature=" + b64EncodedSignature.value() +
		                     "\n");
	}
}

int ServerDaemon::main(const std::vector<std::string>& args) {
	if (!server) {
		return EXIT_FAILURE;
	}

	const auto execution = server->start();
	waitForTerminationRequest();
	execution.stop();

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
