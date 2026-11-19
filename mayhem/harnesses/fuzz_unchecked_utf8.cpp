// Fuzz the unchecked API of utfcpp (utf8::unchecked::). Raw bytes go through
// unchecked::replace_invalid (bounds-checked, accepts any input); the
// unchecked decoders' contract requires valid input, so they run on that
// sanitised result and every result is compared with the checked API.
// The same is done for UTF-16 (input bytes as little-endian pairs) through
// unchecked::replace_invalid16.
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <string>
#include <vector>
#include "utf8.h"

#define CHECK(c) do { if (!(c)) abort(); } while (0)

static void utf8_side(const std::string& raw) {
  std::string s;
  utf8::unchecked::replace_invalid(raw.begin(), raw.end(), std::back_inserter(s));
  CHECK(utf8::is_valid(s.begin(), s.end()));
  {
    std::string c;
    utf8::replace_invalid(raw.begin(), raw.end(), std::back_inserter(c));
    CHECK(c == s);
  }
  std::u16string w16, c16;
  utf8::unchecked::utf8to16(s.begin(), s.end(), std::back_inserter(w16));
  utf8::utf8to16(s.begin(), s.end(), std::back_inserter(c16));
  CHECK(w16 == c16);
  std::u32string w32, c32;
  utf8::unchecked::utf8to32(s.begin(), s.end(), std::back_inserter(w32));
  utf8::utf8to32(s.begin(), s.end(), std::back_inserter(c32));
  CHECK(w32 == c32);
  CHECK(utf8::unchecked::distance(s.begin(), s.end()) ==
        static_cast<ptrdiff_t>(w32.size()));
  std::string back8;
  utf8::unchecked::utf32to8(w32.begin(), w32.end(), std::back_inserter(back8));
  CHECK(back8 == s);
  back8.clear();
  utf8::unchecked::utf16to8(w16.begin(), w16.end(), std::back_inserter(back8));
  CHECK(back8 == s);

  size_t i = 0;
  auto it = s.begin();
  while (it != s.end()) {
    CHECK(utf8::unchecked::peek_next(it) == w32[i]);
    CHECK(utf8::unchecked::next(it) == w32[i]);
    ++i;
  }
  CHECK(i == w32.size());
  while (it != s.begin()) CHECK(utf8::unchecked::prior(it) == w32[--i]);
  utf8::unchecked::advance(it, static_cast<ptrdiff_t>(w32.size()));
  CHECK(it == s.end());
  utf8::unchecked::advance(it, -static_cast<ptrdiff_t>(w32.size()));
  CHECK(it == s.begin());

  using It = std::string::iterator;
  utf8::unchecked::iterator<It> b(s.begin()), e(s.end());
  i = 0;
  for (auto u = b; u != e; ++u) CHECK(*u == w32[i++]);
  CHECK(i == w32.size());
  for (auto u = e; u != b;) { --u; CHECK(*u == w32[--i]); }
}

static void utf16_side(const std::vector<uint16_t>& raw) {
  std::vector<uint16_t> w;
  utf8::unchecked::replace_invalid16(raw.begin(), raw.end(), std::back_inserter(w));
  CHECK(utf8::is_valid16(w.begin(), w.end()));
  {
    std::vector<uint16_t> c;
    utf8::replace_invalid16(raw.begin(), raw.end(), std::back_inserter(c));
    CHECK(c == w);
  }
  std::string s, cs;
  utf8::unchecked::utf16to8(w.begin(), w.end(), std::back_inserter(s));
  utf8::utf16to8(w.begin(), w.end(), std::back_inserter(cs));
  CHECK(s == cs);
  std::vector<utf8::utfchar32_t> cps;
  auto it = w.begin();
  while (it != w.end()) {
    CHECK(utf8::unchecked::peek_next16(it) == utf8::peek_next16(it, w.end()));
    cps.push_back(utf8::unchecked::next16(it));
  }
  size_t i = cps.size();
  while (it != w.begin()) CHECK(utf8::unchecked::prior16(it) == cps[--i]);
  utf8::unchecked::advance16(it, static_cast<ptrdiff_t>(cps.size()));
  CHECK(it == w.end());
  utf8::unchecked::advance16(it, -static_cast<ptrdiff_t>(cps.size()));
  CHECK(it == w.begin());
  std::vector<uint16_t> back;
  for (utf8::utfchar32_t cp : cps) utf8::unchecked::append16(cp, std::back_inserter(back));
  CHECK(back == w);

  using It = std::vector<uint16_t>::iterator;
  utf8::unchecked::iterator16<It> b(w.begin()), e(w.end());
  i = 0;
  for (auto u = b; u != e; ++u) CHECK(*u == cps[i++]);
  CHECK(i == cps.size());
  for (auto u = e; u != b;) { --u; CHECK(*u == cps[--i]); }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  utf8_side(std::string(reinterpret_cast<const char*>(data), size));
  std::vector<uint16_t> raw(size / 2);
  for (size_t i = 0; i < raw.size(); ++i)
    raw[i] = static_cast<uint16_t>(data[2 * i] | (data[2 * i + 1] << 8));
  utf16_side(raw);
  return 0;
}
