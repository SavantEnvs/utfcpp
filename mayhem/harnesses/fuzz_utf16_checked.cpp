// Fuzz the checked UTF-16 API of utfcpp (utf8::*16 and utf16to8) on raw,
// untrusted 16-bit code units (input bytes taken in little-endian pairs).
// Invariants asserted: the validators agree, replace_invalid16 always yields
// valid UTF-16 and keeps valid input unchanged, utf16to8 succeeds exactly on
// valid input and round-trips 16->8->16.
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>
#include "utf8.h"

#define CHECK(c) do { if (!(c)) abort(); } while (0)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::u16string w(size / 2, u'\0');
  for (size_t i = 0; i < size / 2; ++i)
    w[i] = static_cast<char16_t>(data[2 * i] | (data[2 * i + 1] << 8));
  // Exactly-sized heap buffer for the iterator-based API.
  const std::vector<uint16_t> v(w.begin(), w.end());

  const bool valid = utf8::is_valid16(v.begin(), v.end());
  const auto inv = utf8::find_invalid16(v.begin(), v.end());
  CHECK(valid == (inv == v.end()));
  CHECK(valid == utf8::is_valid16(w));
  CHECK(valid == utf8::is_valid16(std::u16string_view(w)));
  const size_t inv_off = utf8::find_invalid16(w);
  CHECK(valid ? inv_off == std::u16string::npos
              : inv_off == static_cast<size_t>(inv - v.begin()));

  const std::u16string fixed = utf8::replace_invalid16(w);
  CHECK(utf8::is_valid16(fixed));
  if (valid) CHECK(fixed == w);
  {
    std::vector<uint16_t> fixed2;
    utf8::replace_invalid16(v.begin(), v.end(), std::back_inserter(fixed2), u'?');
    CHECK(utf8::is_valid16(fixed2.begin(), fixed2.end()));
    CHECK(utf8::replace_invalid16(std::u16string_view(w), u'?') ==
          std::u16string(fixed2.begin(), fixed2.end()));
  }

  try {
    std::string s;
    utf8::utf16to8(v.begin(), v.end(), std::back_inserter(s));
    CHECK(valid);
    CHECK(utf8::is_valid(s));
    CHECK(utf8::utf8to16(s) == w);
    CHECK(utf8::utf16to8(std::u16string_view(w)) == s);
    CHECK(utf8::utf16tou8(w) == std::u8string(s.begin(), s.end()));
  } catch (const utf8::exception&) {
    CHECK(!valid);
  }

  std::vector<utf8::utfchar32_t> fwd;
  try {
    auto it = v.begin();
    while (it < v.end()) {
      auto before = it;
      utf8::utfchar32_t peek = utf8::peek_next16(it, v.end());
      utf8::utfchar32_t cp = utf8::next16(it, v.end());
      CHECK(peek == cp && it > before);
      fwd.push_back(cp);
    }
    CHECK(valid);
    CHECK(static_cast<ptrdiff_t>(fwd.size()) == utf8::distance16(v.begin(), v.end()));
  } catch (const utf8::exception&) {
    CHECK(!valid);
  }
  try {
    auto it = v.end();
    std::vector<utf8::utfchar32_t> bwd;
    while (it != v.begin()) bwd.push_back(utf8::prior16(it, v.begin()));
    if (valid) CHECK(std::vector<utf8::utfchar32_t>(bwd.rbegin(), bwd.rend()) == fwd);
  } catch (const utf8::exception&) {
    CHECK(!valid);
  }
  try {
    auto it = v.begin();
    utf8::advance16(it, static_cast<int>(fwd.size()), v.end());
    if (valid) {
      CHECK(it == v.end());
      utf8::advance16(it, -static_cast<int>(fwd.size()), v.begin());
      CHECK(it == v.begin());
    }
  } catch (const utf8::exception&) {
  }
  try {
    using It = std::vector<uint16_t>::const_iterator;
    utf8::iterator16<It> b(v.begin(), v.begin(), v.end());
    utf8::iterator16<It> e(v.end(), v.begin(), v.end());
    size_t n = 0;
    for (auto i = b; i != e; ++i, ++n) (void)*i;
    CHECK(valid && n == fwd.size());
    for (auto i = e; i != b;) { --i; (void)*i; }
  } catch (const utf8::exception&) {
    CHECK(!valid);
  }
  return 0;
}
