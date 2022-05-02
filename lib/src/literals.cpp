#include "literals.hpp"

const unsigned char* operator""_uc(const char* const str, const unsigned long /* ignored: stringLength */) {
	return reinterpret_cast<const unsigned char*>(str);
}
