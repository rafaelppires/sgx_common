#pragma once

#include <functional>
#include <string>
#include <vector>

bool csv_parse(std::string filename,
               std::function<bool(const std::vector<std::string>&)> f);
void csv_print(const std::string& fname);
std::vector<std::vector<std::string>> csv_tomemory(const std::string& fname);
