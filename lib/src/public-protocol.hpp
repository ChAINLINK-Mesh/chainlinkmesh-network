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
	const constexpr std::uint16_t DEFAULT_CONTROL_PLANE_PORT = 272;
	const constexpr std::uint16_t SHA256_DIGEST_SIZE = 32;
	const constexpr std::uint16_t SHA256_SIGNATURE_SIZE = 256;
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

		static const constexpr std::uint16_t MIN_PACKET_SIZE =
		    sizeof(timestamp) + SHA256_DIGEST_SIZE + sizeof(referringNode) +
		    SHA256_SIGNATURE_SIZE;
		// Size: MIN_PACKET_SIZE + sizeof(csr) ~= 1704 bytes.
		static const constexpr std::uint16_t MAX_PACKET_SIZE =
		    MIN_PACKET_SIZE + MAX_CSR_SIZE;
	};

	struct InitialisationRespPacket {
		using WireGuardPublicKey = Node::WireGuardPublicKey;

		std::uint64_t respondingNode;
		std::uint64_t allocatedNode;
		WireGuardPublicKey respondingWireGuardPublicKey;
		Poco::Net::IPAddress respondingControlPlaneIPAddress;
		Poco::Net::IPAddress respondingWireGuardIPAddress;
		std::uint16_t respondingControlPlanePort;
		std::uint16_t respondingWireGuardPort;
		X509_REQ_RAII signedCSR;

		[[nodiscard]] ByteString get_bytes() const;
		[[nodiscard]] static std::optional<InitialisationRespPacket>
		decode_bytes(const ByteString& bytes);

		const constexpr static std::uint16_t MIN_PACKET_SIZE =
		    sizeof(respondingNode) + sizeof(allocatedNode) + Node::WG_PUBKEY_SIZE +
		    IPV6_ADDR_SIZE + IPV6_ADDR_SIZE + sizeof(respondingControlPlanePort) +
		    sizeof(respondingWireGuardPort);
		const constexpr static std::uint16_t MAX_PACKET_SIZE =
		    MIN_PACKET_SIZE + MAX_CSR_SIZE;
	};

	class PublicConnection;

	class PublicProtocolManager {
	public:
		PublicProtocolManager(std::string psk, const Node& self);
		PublicProtocolManager(const PublicProtocolManager& other);
		virtual ~PublicProtocolManager() = default;

		std::unique_ptr<Poco::Net::TCPServer>
		start(const Poco::Net::ServerSocket& serverSocket,
		      Poco::Net::TCPServerParams::Ptr params);

		std::optional<InitialisationPacket>
		decode_packet(ByteStringView buffer);

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
