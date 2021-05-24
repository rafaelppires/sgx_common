#pragma once

#include <cstdint>
#include <vector>
std::vector<uint8_t> get_rand(size_t len);
void get_rand_inline(size_t len, uint8_t* where);
