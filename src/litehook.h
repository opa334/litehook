#include <stdio.h>
#include <stdbool.h>
#include <mach/mach.h>
#include <mach-o/loader.h>

#ifdef __arm64__
typedef struct mach_header_64 mach_header;
typedef struct segment_command_64 segment_command;
typedef struct section_64 section;
#define LC_SEGMENT_ARCH LC_SEGMENT_64
#else
typedef struct mach_header mach_header;
typedef struct segment_command segment_command;
typedef struct section section;
#define LC_SEGMENT_ARCH LC_SEGMENT
#endif

void *litehook_find_dsc_symbol(const char *imagePath, const char *symbolName);
kern_return_t litehook_hook_function(void *source, void *target);
void litehook_rebind_symbol(const mach_header *sourceHeader, void *replacement, void *replacee);