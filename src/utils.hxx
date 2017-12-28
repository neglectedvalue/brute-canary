#pragma once

#include <iomanip>
#include <iterator>
#include <sstream>

template <typename ForwardIterator>
inline std::string to_hexstring(ForwardIterator first, ForwardIterator finish) {
  std::stringstream ss;

  ss << std::hex;
  for (; first != finish; ++first) {
    ss << std::setw(2) << std::setfill('0') << int{*first};
  }

  return ss.str();
}

template <typename Container>
inline std::string to_hexstring(Container &&c) {
  return to_hexstring(std::cbegin(c), std::cend(c));
}

template <typename ForwardIterator>
inline std::string join(ForwardIterator first, ForwardIterator finish, char const sep) {
  std::stringstream ss;

  if (first != finish) {
    ss << *first++;
  }
  for (; first != finish; ++first) {
    ss << sep << *first;
  }

  return ss.str();
}

template <typename Container>
inline std::string join(Container &&c, char const sep) {
  return join(std::cbegin(c), std::cend(c), sep);
}
