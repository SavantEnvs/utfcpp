// Fuzz the checked UTF-8 API of utfcpp (utf8::) on raw, untrusted bytes:
// validation, replacement, decoding to UTF-16/32, next/prior/advance/distance
// and utf8::iterator, plus the C++11/17/20 string overloads.
// Invariants asserted (abort on violation): the validators agree with each
// other, replace_invalid always yields valid UTF-8 and keeps valid input
// unchanged, and valid input round-trips 8->16->8 and 8->32->8.
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>
#include "utf8.h"

#define CHECK(c) do { if (!(c)) abort(); } while (0)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Exactly-sized heap copy so ASan sees any 1-byte over-read.
  const std::string s(reinterpret_cast<const char*>(data), size);

  const bool valid = utf8::is_valid(s.begin(), s.end());
  const std::string::const_iterator inv = utf8::find_invalid(s.begin(), s.end());
  CHECK(valid == (inv == s.end()));
  CHECK(valid == utf8::is_valid(std::string_view(s)));
  const size_t inv_off = utf8::find_invalid(std::string_view(s));
  CHECK(valid ? inv_off == std::string_view::npos
              : inv_off == static_cast<size_t>(inv - s.begin()));
  CHECK(utf8::find_invalid(s) == inv_off);
  // NUL-terminated overloads stop at the first NUL.
  {
    const char* p = s.c_str();
    const char* q = utf8::find_invalid(p);
    CHECK(q >= p && q <= p + std::strlen(p));
    (void)utf8::is_valid(p);
  }
  (void)utf8::starts_with_bom(s.begin(), s.end());
  (void)utf8::starts_with_bom(std::string_view(s));

  const std::string fixed = utf8::replace_invalid(s);
  CHECK(utf8::is_valid(fixed));
  if (valid) CHECK(fixed == s);
  {
    std::string fixed2;
    utf8::replace_invalid(s.begin(), s.end(), std::back_inserter(fixed2), '?');
    CHECK(utf8::is_valid(fixed2.begin(), fixed2.end()));
    CHECK(utf8::replace_invalid(std::string_view(s), '?') == fixed2);
  }
  {
    std::u8string u8(s.begin(), s.end());
    CHECK(utf8::is_valid(u8) == valid);
    CHECK(utf8::find_invalid(u8) == inv_off);
    CHECK(utf8::is_valid(utf8::replace_invalid(u8)));
  }

  try {
    std::u16string w = utf8::utf8to16(s);
    CHECK(valid);
    CHECK(utf8::utf16to8(w) == s);
    CHECK(utf8::is_valid16(w));
  } catch (const utf8::exception&) {
    CHECK(!valid);
  }
  try {
    std::u32string u = utf8::utf8to32(std::string_view(s));
    CHECK(valid);
    CHECK(utf8::utf32to8(u) == s);
    CHECK(static_cast<ptrdiff_t>(u.size()) == utf8::distance(s.begin(), s.end()));
  } catch (const utf8::exception&) {
    CHECK(!valid);
  }

  // Forward decoding with next(); stops at the first error.
  std::vector<utf8::utfchar32_t> fwd;
  {
    std::string::const_iterator it = s.begin();
    try {
      while (it < s.end()) {
        std::string::const_iterator before = it;
        utf8::utfchar32_t peek = utf8::peek_next(it, s.end());
        utf8::utfchar32_t cp = utf8::next(it, s.end());
        CHECK(peek == cp && it > before);
        fwd.push_back(cp);
      }
      CHECK(valid);
    } catch (const utf8::exception&) {
      CHECK(!valid);
    }
  }
  // Backward decoding with prior(), on any input.
  {
    std::string::const_iterator it = s.end();
    std::vector<utf8::utfchar32_t> bwd;
    try {
      while (it != s.begin()) bwd.push_back(utf8::prior(it, s.begin()));
      if (valid) CHECK(std::vector<utf8::utfchar32_t>(bwd.rbegin(), bwd.rend()) == fwd);
    } catch (const utf8::exception&) {
      CHECK(!valid);
    }
  }
  // advance() forward then back.
  try {
    std::string::const_iterator it = s.begin();
    utf8::advance(it, static_cast<int>(fwd.size()), s.end());
    if (valid) {
      CHECK(it == s.end());
      utf8::advance(it, -static_cast<int>(fwd.size()), s.begin());
      CHECK(it == s.begin());
    }
  } catch (const utf8::exception&) {
  }
  // Checked iterator over the (possibly invalid) range.
  try {
    utf8::iterator<std::string::const_iterator> b(s.begin(), s.begin(), s.end());
    utf8::iterator<std::string::const_iterator> e(s.end(), s.begin(), s.end());
    size_t n = 0;
    for (auto i = b; i != e; ++i, ++n) (void)*i;
    CHECK(valid && n == fwd.size());
    for (auto i = e; i != b;) { --i; (void)*i; }
  } catch (const utf8::exception&) {
    CHECK(!valid);
  }
  return 0;
}
