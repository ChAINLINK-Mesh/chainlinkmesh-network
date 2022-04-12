#pragma once

#include <exception>
#include <variant>

template <typename SuccessType>
using Expected = std::variant<SuccessType, std::exception_ptr>;

template <class... Types>
struct Overload : Types... {
	using Types::operator()...;
};

template <class... Types>
Overload(Types...) -> Overload<Types...>;
