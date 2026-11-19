// Fuzz utf8::unchecked::utf16to8 on raw, untrusted UTF-16 code units (input
// bytes taken in little-endian pairs, an odd trailing byte is ignored).
// unchecked::utf16to8 must not read past `end`, even for a lone lead
// surrogate at the end of the input (upstream issue #78, fixed in 0ee84daac8).
// Uses only API present in utfcpp 3.x so it also builds on old trees.
#include <cstdint>
#include <iterator>
#include <string>
#include <vector>
#include "utf8.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Exactly-sized heap buffer: ASan catches a read one code unit past the end.
  std::vector<uint16_t> w(size / 2);
  for (size_t i = 0; i < w.size(); ++i)
    w[i] = static_cast<uint16_t>(data[2 * i] | (data[2 * i + 1] << 8));
  std::string out;
  utf8::unchecked::utf16to8(w.begin(), w.end(), std::back_inserter(out));
  return 0;
}
