#include "private-protocol.hpp"
#include "certificates.hpp"
#include "private-protocol_generated.h"
#include "wireguard.hpp"

#include <Poco/Net/NetException.h>
#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/TCPServerConnection.h>
#include <exception>
#include <limits>
#include <stdexcept>

extern "C" {
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

#include <memory>
};

namespace PrivateProtocol {
	PrivateProtocolManager::PrivateProtocolManager(Configuration config)
	    : controlPlanePort{ config.controlPlanePort },
	      peers{ std::move(config.peers) }, selfNode{ std::move(
		                                          config.selfNode) } {
		// Prevent nullptr being passed.
		assert(peers);
	}

	std::optional<MessageT> PrivateProtocolManager::decode_packet(
	    const std::span<const std::uint8_t>& bytes) {
		flatbuffers::Verifier verifier{ bytes.data(), bytes.size() };
		if (!VerifyMessageBuffer(verifier)) {
			return std::nullopt;
		}

		MessageT message{};
		GetMessage(bytes.data())->UnPackTo(&message);

		return message;
	}

	std::unique_ptr<Poco::Net::TCPServer>
	PrivateProtocolManager::start(const Poco::Net::ServerSocket& serverSocket,
	                              Poco::Net::TCPServerParams::Ptr params) {
		auto server = std::make_unique<Poco::Net::TCPServer>(
		    new ConnectionFactory(*this), serverSocket, std::move(params));
		server->start();

		return server;
	}

	PrivateProtocolManager::ConnectionFactory::ConnectionFactory(
	    PrivateProtocolManager& parent)
	    : parent{ parent } {}

	Poco::Net::TCPServerConnection*
	PrivateProtocolManager::ConnectionFactory::createConnection(
	    const Poco::Net::StreamSocket& socket) {
		return new PrivateConnection{ socket, parent };
	}

	bool
	PrivateProtocolManager::accept_peer_request(const std::uint64_t originator,
	                                            const Node& node) {
		const auto addedPeer = this->peers->add_peer(node);

		if (addedPeer) {
			for (const auto& neighbour : peers->get_neighbour_peers(selfNode.id)) {
				if (neighbour.id == originator || neighbour.id == node.id) {
					continue;
				}

				// If we have a node's cryptographic details but not their connection
				// details, then don't send to them.
				if (!neighbour.connectionDetails.has_value()) {
					continue;
				}

				inform_node_about_new_peer(neighbour, node);
			}
		}

		return addedPeer;
	}

	void PrivateProtocolManager::inform_node_about_new_peer(const Node& node,
	                                                        const Node& newPeer) {
		// Requires knowing connection details to contact 'node'.
		assert(node.connectionDetails);

		PeerInformCommandT peerInformCommand{};
		peerInformCommand.peer_id = newPeer.id,
		peerInformCommand.certificate = GenericCertificateManager<char>::encode_pem(
		    newPeer.controlPlaneCertificate);
		peerInformCommand.parent = to_flatbuffers(newPeer.parent);

		// If we have connection details for the new peer.
		if (newPeer.connectionDetails) {
			PeerConnectionDetailsT connectionDetails{};
			connectionDetails.wireguard_address =
			    static_cast<std::string>(newPeer.connectionDetails->wireGuardHost);
			connectionDetails.private_proto_port =
			    newPeer.connectionDetails->controlPlanePort;
			peerInformCommand.connection_details =
			    std::make_unique<PeerConnectionDetailsT>(
			        std::move(connectionDetails));
		}

		PrivateProtocol::CommandUnion command{};
		command.Set(peerInformCommand);

		flatbuffers::FlatBufferBuilder fbb{};
		fbb.Finish(command.Pack(fbb));
		const auto fbbBuffer = fbb.GetBufferSpan();

		const auto signature = CertificateManager::sign_data(
		    selfNode.controlPlanePrivateKey,
		    std::span<std::uint8_t>{ fbbBuffer.data(), fbbBuffer.size() });

		// If signing the message failed, don't attempt to send message.
		if (!signature.has_value()) {
			return;
		}

		MessageT message{};
		message.originator = selfNode.id;
		message.command = command;
		message.signature = signature.value();

		PrivateProtocolClient{ node }.send_message(message);
	}

	PrivateConnection::PrivateConnection(const Poco::Net::StreamSocket& socket,
	                                     PrivateProtocolManager& parent)
	    : Poco::Net::TCPServerConnection{ socket }, parent{ parent } {}

	void PrivateConnection::run() {
		Poco::Net::SocketBufVec buf{};
		const auto bytes = socket().receiveBytes(buf);
		const std::span<const std::uint8_t> bufData{
			reinterpret_cast<const std::uint8_t*>(buf.data()), buf.size()
		};

		const auto packet = PrivateProtocolManager::decode_packet(bufData);

		if (!packet) {
			send_error("Could not decode packet");
			return;
		}

		const auto originator = parent.peers->get_peer(packet->originator);

		if (!originator.has_value()) {
			send_error("Unknown origin");
			return;
		}

		flatbuffers::FlatBufferBuilder fbb{};
		fbb.Finish(packet->command.Pack(fbb));
		const auto fbbBuffer = fbb.GetBufferSpan();

		const auto signatureMatches = CertificateManager::check_signature(
		    originator->controlPlanePublicKey,
		    std::span<const std::uint8_t>{ fbbBuffer.data(), fbbBuffer.size() },
		    packet->signature);

		if (!signatureMatches.has_value() || !signatureMatches.value()) {
			send_error("Could not confirm signature");
		}

		switch (packet->command.type) {
			case Command_NONE:
				send_error("Unknown command");
				break;
			case Command_PeerInformCommand:
				handle_peer_inform(packet.value());
				break;
			case Command_ErrorCommand:
				// Don't respond to this. Alternative implementations may have a more
				// advanced error recovery mechanism.
				break;
		}
	}

	void PrivateConnection::send_error(const std::string& errorMsg) {
		ErrorCommandT errorCommand{};
		errorCommand.error = errorMsg;

		flatbuffers::FlatBufferBuilder fbb{};
		fbb.Finish(PrivateProtocol::ErrorCommand::Pack(fbb, &errorCommand));
		const auto fbbBuffer = fbb.GetBufferSpan();

		const auto signature = CertificateManager::sign_data(
		    parent.selfNode.controlPlanePrivateKey,
		    std::span<std::uint8_t>{ fbbBuffer.data(), fbbBuffer.size() });

		// If we fail to sign the error message, don't send it.
		if (!signature.has_value()) {
			return;
		}

		PrivateProtocol::CommandUnion command{};
		command.Set(errorCommand);
		MessageT message{};
		message.originator = parent.selfNode.id;
		message.command = command;
		message.signature = signature.value();

		PrivateProtocolClient::send_message_nowait(socket(), message);
	}

	void PrivateConnection::handle_peer_inform(
	    const PrivateProtocol::MessageT& message) {
		const auto& peerInform = message.command.AsPeerInformCommand();
		const auto peerCertificateChain =
		    GenericCertificateManager<char>::decode_pem_certificate_chain(
		        peerInform->certificate);

		if (!peerCertificateChain.has_value()) {
			send_error("Could not decode peer certificate chain");
			return;
		}

		const auto peerCertificate = peerCertificateChain->back();
		const auto peerPublicKey =
		    CertificateManager::get_certificate_pubkey(peerCertificate);

		if (!peerPublicKey.has_value()) {
			send_error("Could not decode peer certificate chain");
			return;
		}

		X509_NAME* peerSubject = X509_get_subject_name(peerCertificate.get());

		if (peerSubject == nullptr) {
			send_error("Could not decode peer certificate chain");
			return;
		}

		const auto wireguardPublicKeyStr =
		    CertificateManager::get_subject_attribute(peerSubject, NID_userId);

		if (wireguardPublicKeyStr.size() != 1 ||
		    wireguardPublicKeyStr[0].size() !=
		        AbstractWireGuardManager::WG_KEY_SIZE) {
			send_error("Could not decode peer certificate chain");
			return;
		}

		AbstractWireGuardManager::Key wireGuardPublicKey{};
		std::copy(wireguardPublicKeyStr[0].begin(), wireguardPublicKeyStr[0].end(),
		          wireGuardPublicKey.begin());

		const auto peerControlPlaneIP =
		    Node::get_control_plane_ip(peerInform->peer_id);

		std::optional<NodeConnection> nodeConnection{};

		if (peerInform->connection_details != nullptr) {
			Host wireGuardHost =
			    Host{ peerInform->connection_details->wireguard_address };

			nodeConnection = {
				.controlPlanePort = peerInform->connection_details->private_proto_port,
				.wireGuardHost = wireGuardHost,
				.wireGuardPort =
				    wireGuardHost.port().value_or(Node::DEFAULT_WIREGUARD_PORT),
			};
		}

		parent.peers->add_peer(Node{
		    .id = peerInform->peer_id,
		    .controlPlanePublicKey = peerPublicKey.value(),
		    .wireGuardPublicKey = wireGuardPublicKey,
		    .controlPlaneIP = peerControlPlaneIP,
		    .connectionDetails = nodeConnection,
		    .controlPlaneCertificate = peerCertificate,
		    .parent = peerInform->parent,
		});
	}

	PrivateProtocolClient::PrivateProtocolClient(Node peer)
	    : peer{ std::move(peer) } {
		assert(peer.connectionDetails);
	}

	Expected<MessageT>
	PrivateProtocolClient::send_message(const MessageT& message) {
		try {
			Poco::Net::StreamSocket peerSocket{ Poco::Net::SocketAddress{
				  peer.controlPlaneIP,
				  peer.connectionDetails->controlPlanePort,
			} };
			return send_message(peerSocket, message);
		} catch (Poco::InvalidArgumentException& e) {
			return std::make_exception_ptr(e);
		}
	}

	Expected<void>
	PrivateProtocolClient::send_message_nowait(const MessageT& message) {
		try {
			Poco::Net::StreamSocket peerSocket{ Poco::Net::SocketAddress{
				  peer.controlPlaneIP,
				  peer.connectionDetails->controlPlanePort,
			} };

			send_message_nowait(peerSocket, message);
			return std::nullopt;
		} catch (Poco::InvalidArgumentException& e) {
			return std::make_exception_ptr(e);
		}
	}

	Expected<MessageT>
	PrivateProtocolClient::send_message(Poco::Net::StreamSocket& socket,
	                                    const MessageT& message) {
		try {
			send_message_nowait(socket, message);
			Poco::Net::SocketBufVec buf{};
			socket.receiveBytes(buf);
			const std::span<const std::uint8_t> bufData{
				reinterpret_cast<const std::uint8_t*>(buf.data()), buf.size()
			};

			const auto response = PrivateProtocolManager::decode_packet(bufData);

			if (!response.has_value()) {
				return std::make_exception_ptr(
				    std::runtime_error{ "Could not decode response packet" });
			}

			return response.value();
		} catch (Poco::Net::NetException& e) {
			return std::make_exception_ptr(e);
		}
	}

	Expected<void>
	PrivateProtocolClient::send_message_nowait(Poco::Net::StreamSocket& socket,
	                                           const MessageT& message) {
		flatbuffers::FlatBufferBuilder fbb{};
		fbb.Finish(Message::Pack(fbb, &message));

		const auto fbbBuffer = fbb.GetBufferSpan();
		assert(fbbBuffer.size_bytes() < std::numeric_limits<int>::max());

		try {
			socket.sendBytes(fbb.GetBufferSpan().data(),
			                 static_cast<int>(fbb.GetBufferSpan().size_bytes()));
		} catch (Poco::Net::NetException& e) {
			return std::make_exception_ptr(e);
		}

		return std::nullopt;
	}
} // namespace PrivateProtocol
