// Fuzz the code-point encoders of utfcpp: utf8::utf32to8, append, append16
// (checked, throwing on invalid code points) and their unchecked
// counterparts, on untrusted 32-bit code points (input bytes taken as
// little-endian quads). Invariants asserted: the checked encoders throw
// exactly on invalid code points, the output is valid UTF-8/UTF-16, the
// checked and unchecked encoders agree, and the result decodes back.
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>
#include "utf8.h"

#define CHECK(c) do { if (!(c)) abort(); } while (0)

static bool cp_valid(uint32_t cp) {
  return cp <= 0x10ffff && (cp < 0xd800 || cp > 0xdfff);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::u32string u(size / 4, U'\0');
  for (size_t i = 0; i < u.size(); ++i)
    u[i] = static_cast<char32_t>(data[4 * i] | (data[4 * i + 1] << 8) |
                                 (data[4 * i + 2] << 16) |
                                 (static_cast<uint32_t>(data[4 * i + 3]) << 24));
  const std::vector<uint32_t> v(u.begin(), u.end());

  bool all_valid = true;
  for (uint32_t cp : v) all_valid = all_valid && cp_valid(cp);

  try {
    std::string s;
    utf8::utf32to8(v.begin(), v.end(), std::back_inserter(s));
    CHECK(all_valid);
    CHECK(utf8::is_valid(s));
    CHECK(utf8::utf8to32(s) == u);
    CHECK(utf8::utf32to8(std::u32string_view(u)) == s);
    CHECK(utf8::utf32tou8(u) == std::u8string(s.begin(), s.end()));
    std::string us;
    utf8::unchecked::utf32to8(v.begin(), v.end(), std::back_inserter(us));
    CHECK(us == s);
  } catch (const utf8::invalid_code_point&) {
    CHECK(!all_valid);
  }

  std::string s8;
  std::u16string s16;
  std::vector<uint32_t> ok;
  for (uint32_t cp : v) {
    try {
      utf8::append(cp, s8);
      CHECK(cp_valid(cp));
      utf8::append16(cp, s16);
      ok.push_back(cp);
      std::string a, b;
      utf8::append(cp, std::back_inserter(a));
      utf8::unchecked::append(cp, std::back_inserter(b));
      CHECK(a == b);
      std::u16string c, d;
      utf8::append16(cp, std::back_inserter(c));
      utf8::unchecked::append16(cp, std::back_inserter(d));
      CHECK(c == d);
    } catch (const utf8::invalid_code_point&) {
      CHECK(!cp_valid(cp));
    }
  }
  CHECK(utf8::is_valid(s8));
  CHECK(utf8::is_valid16(s16));
  CHECK(utf8::utf8to32(s8) == std::u32string(ok.begin(), ok.end()));
  CHECK(utf8::utf16to8(s16) == s8);
  return 0;
}
