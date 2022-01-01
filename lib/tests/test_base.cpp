#include <cassert>
#include <iostream>

void test();

int main(int argc, char* argv[]) {
	assert(argc > 0);

	std::clog << "Running test \'" << argv[0] << "\': ";

	try {
		test();
		std::clog << "Success";
	} catch (const char* error) {
		std::clog << "Failure: " << error << "\n";
		throw;
	} catch (const std::string& error) {
		std::clog << "Failure: " << error << "\n";
		throw;
	} catch (...) {
		std::clog << "Failure";
		throw;
	}

	std::clog << "\n";
}
