#pragma once

#include <functional>
#include <string>
#include <vector>

void csv_parse(std::string filename,
               std::function<void(const std::vector<std::string>&)> f);
void csv_print(const std::string& fname);
std::vector<std::vector<std::string>> csv_tomemory(const std::string& fname);
