#include <cassert>
#include <iostream>

void test();

int main(int argc, char* argv[]) {
	assert(argc > 0);

	std::clog << "Running test \'" << argv[0] << "\': ";

	try {
		test();
		std::clog << "Success";
	} catch (...) {
		std::clog << "Failure";
	}

	std::clog << "\n";
}