#include <csv.h>
#include <stringtools.h>
#include <sys/stat.h>

#include <fstream>
#include <iostream>

//------------------------------------------------------------------------------
bool csvitem_print(const std::vector<std::string>& item) {
    for (auto& i : item) {
        if (&i != &item[0]) std::cout << " | ";
        std::cout << i;
    }
    std::cout << std::endl;
    return true;
}

//------------------------------------------------------------------------------
bool csvitem_tomemory(std::vector<std::vector<std::string>>& v,
                      const std::vector<std::string>& item) {
    v.push_back(item);
    return true;
}

//------------------------------------------------------------------------------
bool csv_parse(std::string filename,
               std::function<bool(const std::vector<std::string>&)> f) {
    struct stat buffer;
    if (stat(filename.c_str(), &buffer) != 0) {
        std::cerr << "File: " << filename << " not found\n";
        return false;
    }
    std::ifstream fin(filename.c_str());
    std::string line;

    if (fin.good()) {
        std::getline(fin, line);                   // drops first line
        if (!line.empty() && !isdigit(line[0])) {  // unles it starts by a digit
            line.clear();
        }
    }

    bool cont = true;
    while (fin.good() && cont) {
        if (line.empty()) {  // skips reading the first line again
            std::getline(fin, line);
        }
        if (line.empty()) continue;
        if (line[line.size() - 1] == 13) {  // carriage return
            line.erase(line.size() - 1, 1);
        }
        cont = f(split(line, ",", '\"'));
        line.clear();
    }
    return true;
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
