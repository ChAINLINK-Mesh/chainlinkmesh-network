#pragma once
#include <functional>
#include <type_traits>

template <class Callable>
concept VoidReturn = std::is_void_v<std::invoke_result_t<Callable>>;

class ScopeExit {
public:
	template <class Callback>
	explicit ScopeExit(const Callback& function) requires VoidReturn<Callback>
	    : f{ std::move(function) } {}

	~ScopeExit() {
		f();
	};

protected:
	const std::function<void()> f;
};