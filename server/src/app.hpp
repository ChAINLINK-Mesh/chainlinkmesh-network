#pragma once

#include "public-protocol.hpp"
#include "server.hpp"
#include <Poco/Util/AbstractConfiguration.h>
#include <Poco/Util/Application.h>
#include <Poco/Util/OptionCallback.h>
#include <Poco/Util/OptionSet.h>
#include <Poco/Util/ServerApplication.h>
#include <memory>
#include <utility>

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

	Poco::Util::OptionCallback<ServerDaemon> handle_flag();
	void handle_flag_impl(const std::string& flag, const std::string&);

	const constexpr static std::uint16_t DEFAULT_WIREGUARD_PORT = 51820;
	const static CertificateInfo DEFAULT_CERT_INFO;

	/**
	 * @shouldExit Set when processing help options.
	 */
	bool shouldExit = false;

private:
	const constexpr static std::uint32_t ONE_DAY_IN_SECS = 60 * 60 * 24;

protected:
	const constexpr static std::uint32_t MIN_KEY_LENGTH = 2048;
	const constexpr static std::uint32_t MAX_KEY_LENGTH = 4096;
	const constexpr static std::uint32_t MIN_VALIDITY = ONE_DAY_IN_SECS;
	const constexpr static std::uint32_t MAX_VALIDITY =
	    ONE_DAY_IN_SECS * 365 * 10;
};
