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

template <typename SuccessType>
constexpr bool successful(const std::variant<SuccessType, std::exception_ptr>& x) {
	return std::holds_alternative<SuccessType>(x);
}

template <typename SuccessType>
constexpr bool successful(const std::optional<SuccessType>& x) {
	return x.has_value();
}

template <typename SuccessType>
constexpr SuccessType get_expected(const std::variant<SuccessType, std::exception_ptr>& x) {
	return std::get<SuccessType>(x);
}

template <typename SuccessType>
constexpr SuccessType get_expected(const std::optional<SuccessType>& x) {
	return x.value();
}

template <typename SuccessType>
constexpr SuccessType& get_expected(std::variant<SuccessType, std::exception_ptr>& x) {
	return std::get<SuccessType>(x);
}

template <typename SuccessType>
constexpr SuccessType& get_expected(std::optional<SuccessType>& x) {
	return x.value();
}

template <class... Types>
struct Overload : Types... {
	using Types::operator()...;
};

template <class... Types>
Overload(Types...) -> Overload<Types...>;
