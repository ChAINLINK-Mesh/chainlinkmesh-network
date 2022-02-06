#pragma once
#include "certificates.hpp"
#include "node.hpp"
#include "utilities.hpp"
#include <Poco/Net/TCPServer.h>
#include <concepts>
#include <map>
#include <mutex>
#include <optional>
#include <span>

namespace PublicProtocol {
	const constexpr std::uint16_t SHA256_DIGEST_SIZE = 32;
	const constexpr std::uint16_t SHA256_SIGNATURE_SIZE = 256;

	using BufferType = Poco::FIFOBuffer;

	/**
	 * Initialisation packet. The first packet sent by a potential client to a
	 * node capable of authorising connections.
	 */
	struct InitialisationPacket {
		using Hash = std::array<std::uint8_t, SHA256_DIGEST_SIZE>;
		using Signature = std::array<std::uint8_t, SHA256_SIGNATURE_SIZE>;

		std::uint64_t timestamp;
		Hash timestampPSKHash;
		std::uint64_t referringNode;
		Signature timestampPSKSignature;
		// TODO: Require UNSTRUCTUREDNAME to be the node's ID
		// TODO: Require UNSTRUCTUREDADDRESS to be the node's WireGuard public key
		X509_REQ_RAII csr;

		std::strong_ordering operator<=>(const InitialisationPacket& other) const;
		bool operator==(const InitialisationPacket& other) const;
		bool operator!=(const InitialisationPacket& other) const = default;
	};

	struct InitialisationRespPacket {
		using WireGuardPublicKey = Node::WireGuardPublicKey;

		std::uint64_t respondingNode;
		std::uint64_t allocatedNode;
		WireGuardPublicKey respondingPublicKey;
		Poco::Net::IPAddress respondingMeshIPAddress;
		Poco::Net::IPAddress respondingWireguardIPAddress;
		std::uint16_t respondingControlPlanePort;
		std::uint16_t respondingWireguardPort;
		X509_REQ_RAII signedCSR;

		[[nodiscard]] ByteString get_bytes() const;
	};

	class PublicConnection;

	class PublicProtocolManager {
	public:
		PublicProtocolManager(std::string psk, const Node& self);
		PublicProtocolManager(const PublicProtocolManager& other);
		virtual ~PublicProtocolManager() = default;

		void start(const Poco::Net::ServerSocket& serverSocket,
		           Poco::Net::TCPServerParams::Ptr params);

		std::optional<InitialisationPacket>
		decode_packet(std::span<const char> buffer);

		std::optional<InitialisationRespPacket>
		create_response(InitialisationPacket packet);

		bool add_node(const Node& node);
		std::optional<Node> get_node(std::uint64_t nodeID) const;
		bool delete_node(const Node& node);

	protected:
		const std::string psk;
		const Node selfNode;
		mutable std::mutex nodesMutex;
		std::map<std::uint64_t, Node> nodes;

		std::optional<InitialisationPacket> decode_packet(BufferType& buffer) const;

		static const constexpr std::uint16_t SHA256_DIGEST_B64_SIZE =
		    base64_encoded_character_count(SHA256_DIGEST_SIZE);
		static const constexpr std::uint16_t SHA256_SIGNATURE_B64_SIZE =
		    base64_encoded_character_count(SHA256_SIGNATURE_SIZE);
		static const constexpr std::uint16_t MIN_PACKET_BUFFER_SIZE =
		    sizeof(InitialisationPacket::timestamp) + SHA256_DIGEST_B64_SIZE +
		    sizeof(InitialisationPacket::referringNode) + SHA256_SIGNATURE_B64_SIZE;
		static const constexpr std::uint16_t MAX_CSR_SIZE = 1200;
		// Size: MIN_PACKET_BUFFER_SIZE + sizeof(csr) ~= 1675 bytes.
		static const constexpr std::uint16_t INIT_PACKET_BUFFER_SIZE =
		    MIN_PACKET_BUFFER_SIZE + MAX_CSR_SIZE;

		static std::optional<EVP_PKEY_RAII> get_node_pkey(const Node& node);

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
} // namespace PublicProtocol
