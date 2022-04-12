#include "test.hpp"
#include "literals.hpp"
#include "utilities.hpp"

void test_trim();
void test_base64();

void test() {
	test_trim();
	test_base64();
}

void test_trim() {
	if (trim("word") != "word") {
		throw "trim() doesn't handle no whitespace";
	}

	if (trim(" a") != "a") {
		throw "trim() doesn't handle preceeding whitespace";
	}

	if (trim("a ") != "a") {
		throw "trim() doesn't handle following whitespace";
	}

	if (trim(" a ") != "a") {
		throw "trim() doesn't handle preceding and following whitespace";
	}

	if (trim("  a  ") != "a") {
		throw "trim() doesn't handle multiple preceding and following whitespace";
	}

	if (trim(" integrated space ") != "integrated space") {
		throw "trim() doesn't handle integrated spaces";
	}
}

void test_base64() {
	if (base64_decode("") != ByteString{}) {
		throw "base64_decode() doesn't handle empty strings";
	}

	if (base64_decode("=").has_value()) {
		throw "base64_decode() doesn't reject empty padding strings";
	}

	if (base64_decode("YWJj") != "abc"_uc) {
		throw "base64_decode() doesn't handle valid non-padded Base64 string";
	}

	if (base64_decode("YQ==") != "a"_uc) {
		throw "base64_decode() doesn't handle valid padded Base64 string";
	}

	// We reject invalid Base64 strings to prevent further damage by
	// misinterpretation.
	if (base64_decode(" YWJj ").has_value()) {
		throw "base64_decode() doesn't reject Base64 strings with whitespace";
	}

	if (base64_decode("YWJj*").has_value()) {
		throw "base64_decode() doesn't reject Base64 strings with symbols";
	}
}
