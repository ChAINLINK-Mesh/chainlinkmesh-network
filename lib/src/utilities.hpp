#pragma once
#include <iterator>

/**
 * Compares ranges [begin1..end1) to [begin2..)
 *
 * Assumes that the ranges have equal length.
 *
 * @param begin1 - the start iterator of the first range
 * @param end1 - the iterator past the end of the first range
 * @param begin2 - the start iterator of the second range
 * @return the lexicographical comparison of the two ranges
 */
template <std::input_iterator Iter>
std::strong_ordering compare(Iter begin1, Iter end1, Iter begin2) {
	for (; begin1 != end1; begin1++, begin2++) {
		if (const auto cmp = (*begin1 <= > *begin2); cmp != 0) {
			return cmp;
		}
	}

	return std::strong_ordering::equal;
}
