#pragma once

#include "private-protocol_generated.h"

#include <cstdint>
#include <optional>
#include <span>

namespace PrivateProtocol {
	const constexpr std::uint16_t DEFAULT_CONTROL_PLANE_PORT = 273;

	class PrivateProtocolManager {
	public:
		struct Configuration {
			std::uint16_t controlPlanePort;
		};

		PrivateProtocolManager(Configuration config);
		PrivateProtocolManager(const PrivateProtocolManager& other) = default;
		virtual ~PrivateProtocolManager() = default;

		static std::optional<MessageT>
		decode_packet(const std::span<std::uint8_t>& bytes);

	protected:
		std::uint16_t controlPlanePort;
	};
} // namespace PrivateProtocol
