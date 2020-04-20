#include "libcpp_mock.h"

namespace std {
int rand() { return ::rand(); }
}  // namespace std
