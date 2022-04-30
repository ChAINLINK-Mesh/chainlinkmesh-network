#include "private-protocol.hpp"

namespace PrivateProtocol {
	PrivateProtocolManager::PrivateProtocolManager(const Configuration& config)
	    : controlPlanePort{ config.controlPlanePort }, peers{ config.peers } {
		// Prevent nullptr being passed.
		assert(config.peers);
	}

	std::optional<MessageT>
	PrivateProtocolManager::decode_packet(const std::span<std::uint8_t>& bytes) {
		flatbuffers::Verifier verifier{ bytes.data(), bytes.size() };
		if (!VerifyMessageBuffer(verifier)) {
			return std::nullopt;
		}

		MessageT message{};
		GetMessage(bytes.data())->UnPackTo(&message);

		return message;
	}
} // namespace PrivateProtocol