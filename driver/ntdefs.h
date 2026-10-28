
static __inline size_t VnStrLenA(const char* s) { size_t n = 0; while (s[n]) n++; return n; }
static __inline size_t VnStrLenW(const wchar_t* s) { size_t n = 0; while (s[n]) n++; return n; }

typedef enum _SYSTEM_INFORMATION_CLASS { SystemBasicInformation = 0 } SYSTEM_INFORMATION_CLASS;
