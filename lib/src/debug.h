#pragma once

#ifdef NDEBUG
#	define DEBUG_MODE false
#else
#	define DEBUG_MODE true
#endif

/**
 * @brief Performs a check if in debug mode.
 *
 * @param condition check to perform
 * @return false if release mode, else the condition
 */
constexpr bool debug_check(bool condition) {
	if constexpr (DEBUG_MODE) {
		return condition;
	}

	return false;
}
