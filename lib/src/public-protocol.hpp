#pragma once

#include "certificates.hpp"
#include "clock.hpp"
#include "error.hpp"
#include "node.hpp"
#include "peers.hpp"
#include "utilities.hpp"
#include "wireguard.hpp"

#include <Poco/Logger.h>
#include <Poco/Net/IPAddress.h>
#include <Poco/Net/TCPServer.h>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <span>

namespace PublicProtocol {
	const constexpr std::uint16_t DEFAULT_CONTROL_PLANE_PORT = 272;
	const constexpr std::uint16_t MAX_CSR_SIZE = 1400;
	const constexpr std::uint16_t SHA256_DIGEST_B64_SIZE =
	    base64_encoded_character_count(SHA256_DIGEST_SIZE);
	const constexpr std::uint16_t SHA256_SIGNATURE_B64_SIZE =
	    base64_encoded_character_count(SHA256_SIGNATURE_SIZE);
	const constexpr std::uint16_t IPV6_ADDR_SIZE = 16;

	using BufferType = Poco::FIFOBuffer;

	/**
	 * Initialisation packet. The first packet sent by a potential client to a
	 * node capable of authorising connections.
	 */
	struct InitialisationPacket {
		using Hash = SHA256_Hash;
		using Signature = SHA256_Signature;

		std::uint64_t timestamp;
		Hash timestampPSKHash;
		std::uint64_t referringNode;
		Signature timestampPSKSignature;
		// TODO: Require UNSTRUCTUREDADDRESS to be the node's WireGuard public key
		X509_REQ_RAII csr;

		[[nodiscard]] ByteString get_bytes() const;
		std::strong_ordering operator<=>(const InitialisationPacket& other) const;
		bool operator==(const InitialisationPacket& other) const;
		bool operator!=(const InitialisationPacket& other) const = default;

		static const constexpr std::uint16_t MIN_PACKET_SIZE =
		    sizeof(timestamp) + SHA256_DIGEST_SIZE + sizeof(referringNode) +
		    SHA256_SIGNATURE_SIZE;
		// Size: MIN_PACKET_SIZE + sizeof(csr) ~= 1704 bytes.
		static const constexpr std::uint16_t MAX_PACKET_SIZE =
		    MIN_PACKET_SIZE + MAX_CSR_SIZE;
	};

	struct InitialisationRespPacket {
		using WireGuardPublicKey = AbstractWireGuardManager::Key;

		std::uint64_t respondingNode;
		std::uint64_t allocatedNode;
		WireGuardPublicKey respondingWireGuardPublicKey;
		Poco::Net::IPAddress respondingControlPlaneIPAddress;
		Poco::Net::IPAddress respondingWireGuardIPAddress;
		std::uint16_t respondingControlPlanePort;
		std::uint16_t respondingWireGuardPort;
		X509_RAII signedCSR;

		[[nodiscard]] ByteString get_bytes() const;
		[[nodiscard]] static std::optional<InitialisationRespPacket>
		decode_bytes(const ByteString& bytes);

		const constexpr static std::uint16_t MIN_PACKET_SIZE =
		    sizeof(respondingNode) + sizeof(allocatedNode) +
		    AbstractWireGuardManager::WG_KEY_SIZE + IPV6_ADDR_SIZE +
		    IPV6_ADDR_SIZE + sizeof(respondingControlPlanePort) +
		    sizeof(respondingWireGuardPort);
		const constexpr static std::uint16_t MAX_PACKET_SIZE =
		    MIN_PACKET_SIZE + MAX_CSR_SIZE;
	};

	class PublicConnection;

	class PublicProtocolManager {
	public:
		struct Configuration {
			ByteString psk;
			Node self;
			EVP_PKEY_RAII controlPlanePrivateKey;
			std::uint64_t pskTTL;
			Clock clock;
			std::shared_ptr<Peers> peers;
			std::default_random_engine randomEngine;
		};

		PublicProtocolManager(Configuration config);
		PublicProtocolManager(const PublicProtocolManager& other);
		virtual ~PublicProtocolManager() = default;

		std::unique_ptr<Poco::Net::TCPServer>
		start(const Poco::Net::ServerSocket& serverSocket,
		      Poco::Net::TCPServerParams::Ptr params);

		std::optional<InitialisationPacket> decode_packet(ByteStringView buffer);

		std::optional<InitialisationRespPacket>
		create_response(InitialisationPacket packet);

		// TODO: Review this validity period.
		static const constexpr std::uint64_t DEFAULT_CERTIFICATE_VALIDITY_SECONDS =
		    900ULL * 24ULL * 60ULL * 60ULL;

		ByteString get_psk() const;
		std::optional<std::tuple<std::uint64_t, SHA256_Hash, SHA256_Signature>>
		get_signed_psk() const;

		std::vector<Node> get_peer_nodes() const;

		const constexpr static std::uint64_t DEFAULT_PSK_TTL = 120;
		static const ByteString DEFAULT_PSK;

	protected:
		const ByteString psk;
		const Node selfNode;
		const EVP_PKEY_RAII controlPlanePrivateKey;
		std::uint64_t pskTTL;
		const Clock clock;
		std::uniform_int_distribution<std::uint64_t> idDistribution;
		std::default_random_engine randomEngine;
		std::shared_ptr<Peers> peers;

		std::optional<InitialisationPacket> decode_packet(BufferType& buffer) const;

		class ConnectionFactory : public Poco::Net::TCPServerConnectionFactory {
		public:
			ConnectionFactory(PublicProtocolManager& parent);
			~ConnectionFactory() override = default;

			Poco::Net::TCPServerConnection*
			createConnection(const Poco::Net::StreamSocket& socket) override;

		protected:
			PublicProtocolManager& parent;
		};

		friend PublicConnection;
	};

	class PublicConnection : public Poco::Net::TCPServerConnection {
	public:
		PublicConnection(const Poco::Net::StreamSocket& socket,
		                 PublicProtocolManager& parent);
		~PublicConnection() override = default;

		void run() override;

	protected:
		PublicProtocolManager& parent;
	};

	class PublicProtocolClient {
	public:
		struct Configuration {
			CertificateInfo certInfo;
			Host parentAddress;
			PublicProtocol::InitialisationPacket::Hash pskHash;
			PublicProtocol::InitialisationPacket::Signature pskSignature;
			std::uint64_t referringNode;
			std::uint64_t timestamp;
		};

		PublicProtocolClient(Configuration config);
		virtual ~PublicProtocolClient() = default;

		InitialisationRespPacket connect();
		[[nodiscard]] Host
		get_parent_address(const InitialisationRespPacket& response) const;

	protected:
		Configuration config;
	};
} // namespace PublicProtocol
