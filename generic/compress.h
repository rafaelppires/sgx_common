#pragma once
#include <string>

std::string compress(const char *buff, size_t n);
template <typename T>
std::string compress(const T &t) {
    return compress(t.data(), t.size());
}

std::string decompress(const char *buff, size_t n);
template <typename T>
std::string decompress(const T &t) {
    return decompress(t.data(), t.size());
}
