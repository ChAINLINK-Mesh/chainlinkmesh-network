#pragma once

#include "peers.hpp"
#include "private-protocol_generated.h"

#include <cstdint>
#include <optional>
#include <span>

namespace PrivateProtocol {
	const constexpr std::uint16_t DEFAULT_CONTROL_PLANE_PORT = 273;

	class PrivateProtocolManager {
	public:
		struct Configuration {
			/**
			 * @controlPlanePort What port to run the private protocol on.
			 */
			std::uint16_t controlPlanePort;

			/**
			 * @peers A shared pointer to the list of peers. Not permitted to be
			 * nullptr.
			 */
			std::shared_ptr<Peers> peers;
		};

		/**
		 * @brief Creates a new Private-Protocol Manager from the given
		 * configuration.
		 *
		 * @param config The initial configuration to start with.
		 */
		PrivateProtocolManager(const Configuration& config);

		/**
		 * @brief Creates a copy of a Private-Protocol Manager. Will create a
		 * duplicate of the other Private-Protocol Manager's peer list, i.e.
		 * subsequent changes will not affect both managers.
		 *
		 * @param other The other Private-Protocol Manager.
		 */
		PrivateProtocolManager(const PrivateProtocolManager& other) = default;
		virtual ~PrivateProtocolManager() = default;

		/**
		 * @brief Decodes a given sequence of bytes into the appropriate packet.
		 *
		 * @param bytes Sequence of bytes to decode.
		 */
		static std::optional<MessageT>
		decode_packet(const std::span<std::uint8_t>& bytes);

	protected:
		std::uint16_t controlPlanePort;
		std::shared_ptr<Peers> peers;
	};
} // namespace PrivateProtocol
