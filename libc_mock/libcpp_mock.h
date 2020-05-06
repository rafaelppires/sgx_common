#pragma once

#include <libc_mock/libc_proxy.h>
#include <sys/types.h>

#include <string>
extern "C" {
extern int printf(const char *fmt, ...);
}

namespace std {

using ::lconv;
using ::localeconv;
typedef ssize_t streamsize;

//------------------------------------------------------------------------------
struct ios_base {
    streamsize precision(streamsize prec) { return 5; }
    streamsize width() const;
    streamsize width(streamsize __wide);

   private:
    streamsize __width_;
};

//------------------------------------------------------------------------------
struct ios : public ios_base {
    char fill() const;
    char fill(char __ch);
    ios &copyfmt(const ios &__rhs);

   private:
    char __fill_;
};

//------------------------------------------------------------------------------
class ostream : public ios {
   public:
    ostream &put(char c);
    ostream &flush();

    ostream &operator<<(int);
    ostream &operator<<(long);
    ostream &operator<<(float);
    ostream &operator<<(double);
    ostream &operator<<(unsigned);
    ostream &operator<<(long unsigned);
    ostream &operator<<(const std::string &s);
    ostream &operator<<(ostream &f(ostream &));

   protected:
    std::string buffer_;
};

//------------------------------------------------------------------------------
struct stringstream : public ostream {
    stringstream() {}
    stringstream(const std::string &s) { buffer_ = s; }

    void write(const char *p, size_t sz) { buffer_ += std::string(p, sz); }

    void read(char *out, size_t sz) {
        size_t rd = 0;
        memcpy(out, buffer_.c_str(), rd = std::min(sz, buffer_.size()));
        buffer_.erase(0, rd);
    }

    std::string str() { return buffer_; }
};

//------------------------------------------------------------------------------
struct ostringstream : public ostream {
    string str() const { return buffer_; }
    void str(const string &s) { buffer_ = s; };
};

//------------------------------------------------------------------------------
ostream &endl(ostream &out);
extern ostream cout;

struct istream {};

int rand();

//------------------------- to_string ------------------------------------------
template <typename T>
inline std::string to_string(T x) {
    char buf[100];
    snprintf(buf, sizeof(buf), "%d", x);
    return std::string(buf);
}

template <typename T>
inline std::string to_string(long x) {
    char buf[100];
    snprintf(buf, sizeof(buf), "%ld", x);
    return std::string(buf);
}

template <typename T>
inline std::string to_string(unsigned x) {
    char buf[100];
    snprintf(buf, sizeof(buf), "%u", x);
    return std::string(buf);
}

template <>
inline std::string to_string(float x) {
    char buf[100];
    snprintf(buf, sizeof(buf), "%f", x);
    return std::string(buf);
}

template <>
inline std::string to_string(long unsigned int x) {
    char buf[100];
    snprintf(buf, sizeof(buf), "%lu", x);
    return std::string(buf);
}

//------------------------------------------------------------------------------
/*
inline bool getline(stringstream &ss, std::string &s, char delim) {
    size_t nl = ss.buffer_.find(delim);
    if (nl == std::string::npos) {
        if (!ss.buffer_.empty()) {
            s = ss.buffer_;
            ss.buffer_.clear();
            return true;
        } else {
            return false;
        }
    }
    s = ss.buffer_.substr(0, nl);
    ss.buffer_.erase(0, nl + 1);
    return true;
}*/

}  // namespace std
