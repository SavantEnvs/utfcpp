// Disable LeakSanitizer at build time (leaks are not the bug class fuzzed here); ASan/UBSan stay on.
extern "C" int __lsan_is_turned_off() { return 1; }
