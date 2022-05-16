#pragma once

#include <exception>
#include <optional>
#include <variant>

template <typename SuccessType>
struct ExpectedWrapper {
	using type = std::variant<SuccessType, std::exception_ptr>;
};

template <>
struct ExpectedWrapper<void> {
	using type = std::optional<std::exception_ptr>;
};

template <typename SuccessType>
using Expected = typename ExpectedWrapper<SuccessType>::type;

template <class... Types>
struct Overload : Types... {
	using Types::operator()...;
};

template <class... Types>
Overload(Types...) -> Overload<Types...>;
