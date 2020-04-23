#include <csv.h>
#include <stringutils.h>

#include <fstream>
#include <iostream>

//------------------------------------------------------------------------------
void csvitem_print(const std::vector<std::string>& item) {
    for (auto& i : item) {
        if (&i != &item[0]) std::cout << " | ";
        std::cout << i;
    }
    std::cout << std::endl;
}

//------------------------------------------------------------------------------
void csvitem_tomemory(std::vector<std::vector<std::string>>& v,
                      const std::vector<std::string>& item) {
    v.push_back(item);
}

//------------------------------------------------------------------------------
void csv_parse(std::string filename,
               std::function<void(const std::vector<std::string>&)> f) {
    std::ifstream fin(filename.c_str());
    while (fin.good()) {
        std::string line;
        std::getline(fin, line);
        if (line.empty()) continue;
        if (line[line.size() - 1] == 13) {  // carriage return
            line.erase(line.size() - 1, 1);
        }
        f(split(line, ",", '\"'));
    }
}

//------------------------------------------------------------------------------
void csv_print(const std::string& fname) { csv_parse(fname, csvitem_print); }

//------------------------------------------------------------------------------
std::vector<std::vector<std::string>> csv_tomemory(const std::string& fname) {
    std::vector<std::vector<std::string>> out;
    csv_parse(fname, std::bind(csvitem_tomemory, std::ref(out),
                               std::placeholders::_1));
    return out;
}

//------------------------------------------------------------------------------
