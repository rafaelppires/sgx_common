#include "libcpp_mock.h"

namespace std {

//------------------ ostream ---------------------------------------------------
ostream cout;

ostream &ostream::operator<<(const std::string &s) {
    buffer_ += s;
    return *this;
}

ostream &ostream::operator<<(float f) {
    *this << to_string(f);
    return *this;
}

ostream& endl(ostream& out) {
    out.put('\n');
    out.flush();
    return out;
}

ostream& ostream::put(char c) {
    buffer_ += c;
    return *this;
}

ostream& ostream::flush() {
    printf("%s", buffer_.c_str());
    buffer_.clear();
    return *this;
}

int rand() { return ::rand(); }

//------------------ ios_base ---------------------------------------------------
streamsize ios_base::width() const { return __width_; }

streamsize ios_base::width(streamsize __wide) {
    streamsize __r = __width_;
    __width_ = __wide;
    return __r;
}

char ios::fill() const {
    // if (traits_type::eq_int_type(traits_type::eof(), __fill_))
    //    __fill_ = widen(' ');
    return __fill_;
}

char ios::fill(char __ch) {
    char __r = __fill_;
    __fill_ = __ch;
    return __r;
}

ios& ios::copyfmt(const ios& __rhs) {
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
}  // namespace std
