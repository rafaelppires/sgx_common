#include <stringutils.h>

std::vector<std::string> split(const std::string& str, const std::string& delim,
                               char escape) {
    std::vector<std::string> parts;
    size_t start = -1, end = 0, found;
    bool scaping = false, skip = false;
    std::string tokens = delim;
    if (escape != 0) tokens += escape;
    while (end < str.size()) {
        end = start + 1;
        while (end < str.size()) {
            found = tokens.find(str[end]);
            if (found == std::string::npos) {
                end++;
            } else if (escape != 0 && tokens[found] == escape) {
                scaping = !scaping;
                if (scaping) {
                    ++start;
                    ++end;
                    tokens = escape;
                } else {
                    tokens = delim + escape;
                    skip = true;
                    break;
                }
            } else if (skip) {
                skip = false;
                start = end++;
            } else {
                break;
            }
        }
        parts.push_back(std::string(str, start + 1, end - start - 1));
        start = end;
    }
    return parts;
}
