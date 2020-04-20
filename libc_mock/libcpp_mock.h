#pragma once

#include <libc_mock/libc_proxy.h>
#include <sys/types.h>

#include <string>

namespace std {

using ::lconv;
using ::localeconv;
typedef ssize_t streamsize;

struct ios_base {
    streamsize precision(streamsize prec) { return 5; }
    streamsize width() const { return __width_; }
    streamsize width(streamsize __wide) {
        streamsize __r = __width_;
        __width_ = __wide;
        return __r;
    }

   private:
    streamsize __width_;
};

struct ios : public ios_base {
    char fill() const {
        // if (traits_type::eq_int_type(traits_type::eof(), __fill_))
        //    __fill_ = widen(' ');
        return __fill_;
    }

    char fill(char __ch) {
        char __r = __fill_;
        __fill_ = __ch;
        return __r;
    }

    ios &copyfmt(const ios &__rhs) {
        if (this != &__rhs) {
            //__call_callbacks(erase_event);
            // ios_base::copyfmt(__rhs);
            //__tie_ = __rhs.__tie_;
            __fill_ = __rhs.__fill_;
            //__call_callbacks(copyfmt_event);
            // exceptions(__rhs.exceptions());
        }
        return *this;
    }

   private:
    char __fill_;
};

struct ostream : public ios {
    ostream &operator<<(float f) { return *this; }
    ostream &operator<<(const std::string &s) { return *this; }
};

struct istream {};

int rand();

template <typename T>
inline std::string to_string(T x) {
    char buf[100];
    snprintf(buf, sizeof(buf), "%d", x);
    return std::string(buf);
}

template <>
inline std::string to_string(long unsigned int x) {
    char buf[100];
    snprintf(buf, sizeof(buf), "%lu", x);
    return std::string(buf);
}

struct stringstream : public ostream {
    stringstream() {}
    stringstream(const std::string &s) : buffer(s) {}

    void write(const char *p, size_t sz) { buffer += std::string(p, sz); }

    void read(char *out, size_t sz) {
        size_t rd = 0;
        memcpy(out, buffer.c_str(), rd = std::min(sz, buffer.size()));
        buffer.erase(0, rd);
    }

    stringstream &operator<<(const std::string &in) {
        buffer += in;
        return *this;
    }

    std::string str() { return buffer; }

    std::string buffer;
};

inline bool getline(stringstream &ss, std::string &s, char delim) {
    size_t nl = ss.buffer.find(delim);
    if (nl == std::string::npos) {
        if (!ss.buffer.empty()) {
            s = ss.buffer;
            ss.buffer.clear();
            return true;
        } else {
            return false;
        }
    }
    s = ss.buffer.substr(0, nl);
    ss.buffer.erase(0, nl + 1);
    return true;
}

}  // namespace std

