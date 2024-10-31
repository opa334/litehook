#include "litehook.h"
#include <stdarg.h>
#include <stdbool.h>
#include <sys/types.h>
#include <string.h>
#include <sys/fcntl.h>
#include <mach/mach.h>
#include <mach/arm/kern_return.h>
#include <mach/port.h>
#include <mach/vm_prot.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <dlfcn.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>
#include <sys/syslimits.h>
#include <dispatch/dispatch.h>
#include <dyld_cache_format.h>
#include <ptrauth.h>

size_t _lth_fstrlen(FILE *f)
{
	size_t sz = 0;
	uint32_t prev = ftell(f);
	while (true) {
		char c = 0;
		if (fread(&c, sizeof(c), 1, f) != 1) break;
		if (c == 0) break;
		sz++;
	}
	fseek(f, prev, SEEK_SET);
	return sz;
}

uint32_t _lth_arm64_gen_movk(uint8_t x, uint16_t val, uint16_t lsl)
{
	uint32_t base = 0b11110010100000000000000000000000;

	uint32_t hw = 0;
	if (lsl == 16) {
		hw = 0b01 << 21;
	}
	else if (lsl == 32) {
		hw = 0b10 << 21;
	}
	else if (lsl == 48) {
		hw = 0b11 << 21;
	}

	uint32_t imm16 = (uint32_t)val << 5;
	uint32_t rd = x & 0x1F;

	return base | hw | imm16 | rd;
}

uint32_t _lth_arm64_gen_br(uint8_t x)
{
	uint32_t base = 0b11010110000111110000000000000000;
	uint32_t rn = ((uint32_t)x & 0x1F) << 5;
	return base | rn;
}

__attribute__((noinline, naked)) volatile kern_return_t litehook_vm_protect(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
#ifdef __arm64__
	__asm("mov x16, #-14");
	__asm("svc 0x80");
	__asm("ret");
#else
	// broken....
	__asm("mov r12, #-14");
	__asm("svc 0x80");
	__asm("bx lr");
#endif
}

kern_return_t litehook_unprotect(vm_address_t addr, vm_size_t size)
{
	return litehook_vm_protect(mach_task_self(), addr, size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
}

kern_return_t litehook_protect(vm_address_t addr, vm_size_t size)
{
	return litehook_vm_protect(mach_task_self(), addr, size, false, VM_PROT_READ | VM_PROT_EXECUTE);
}

kern_return_t litehook_hook_function(void *source, void *target)
{
	kern_return_t kr = KERN_SUCCESS;

	uint32_t *toHook = (uint32_t*)ptrauth_strip(source, ptrauth_key_function_pointer);
	uint64_t targetAddr = (uint64_t)ptrauth_strip(target, ptrauth_key_function_pointer);

	kr = litehook_unprotect((vm_address_t)toHook, 5*4);
	if (kr != KERN_SUCCESS) return kr;

	toHook[0] = _lth_arm64_gen_movk(16, targetAddr >>  0,  0);
	toHook[1] = _lth_arm64_gen_movk(16, targetAddr >> 16, 16);
	toHook[2] = _lth_arm64_gen_movk(16, targetAddr >> 32, 32);
	toHook[3] = _lth_arm64_gen_movk(16, targetAddr >> 48, 48);
	toHook[4] = _lth_arm64_gen_br(16);
	uint32_t hookSize = 5 * sizeof(uint32_t);

	kr = litehook_protect((vm_address_t)toHook, hookSize);
	if (kr != KERN_SUCCESS) return kr;

	sys_icache_invalidate(toHook, hookSize);

	return KERN_SUCCESS;
}

void _litehook_rebind_symbol_in_section(const mach_header *sourceHeader, section *section, void *replacee, void *replacement)
{
	char segname[sizeof(section->segname)+1];
	strlcpy(segname, section->segname, sizeof(segname));
	char sectname[sizeof(section->sectname)+1];
	strlcpy(sectname, section->sectname, sizeof(sectname));

	unsigned long sectionSize = 0;
	uint8_t *sectionStart = getsectiondata(sourceHeader, segname, sectname, &sectionSize);

	bool auth = !strcmp(sectname, "__auth_got");

	void **symbolPointers = (void **)sectionStart;
	replacee = ptrauth_strip(ptrauth_auth_function(replacee, ptrauth_key_function_pointer, 0), ptrauth_key_function_pointer);

	for (uint32_t i = 0; i < (sectionSize / sizeof(void *)); i++) {
		void *symbolPointer = symbolPointers[i];
		if (auth) symbolPointer = ptrauth_strip(ptrauth_auth_function(symbolPointers[i], ptrauth_key_function_pointer, &symbolPointers[i]), ptrauth_key_function_pointer);
		printf("%p: %p vs %p\n", &symbolPointers[i], symbolPointer, replacee);
		if (symbolPointer == replacee) {
			litehook_unprotect((vm_address_t)&symbolPointers[i], sizeof(void *));
			if (auth) replacement = ptrauth_auth_and_resign(replacement, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, &symbolPointers[i]);
			symbolPointers[i] = replacement;
		}
	}
}

void litehook_rebind_symbol(const mach_header *sourceHeader, void *replacee, void *replacement)
{
	struct load_command *lcp = (void *)((uintptr_t)sourceHeader + sizeof(mach_header));
	for(int i = 0; i < sourceHeader->ncmds; i++) {
		if (lcp->cmd == LC_SEGMENT_ARCH) {
			segment_command *segCmd = (segment_command *)lcp;
			if (!strncmp(segCmd->segname, "__AUTH_CONST", sizeof(segCmd->segname)) ||
				!strncmp(segCmd->segname, "__DATA_CONST", sizeof(segCmd->segname)) ||
				!strncmp(segCmd->segname, "__DATA", sizeof(segCmd->segname))) {
				section *sections = (void *)((uintptr_t)lcp + sizeof(segment_command));
				for (int j = 0; j < segCmd->nsects; j++) {
					if ((sections[j].flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS || 
						(sections[j].flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
						_litehook_rebind_symbol_in_section(sourceHeader, &sections[j], replacee, replacement);
					}
				}
			}
		}
		lcp = (void *)((uintptr_t)lcp + lcp->cmdsize);
	}
}

const char *litehook_locate_dsc(void)
{
	static char dscPath[PATH_MAX] = {};
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		char *dyldSharedRegion   = getenv("DYLD_SHARED_REGION");
		char *dyldSharedCacheDir = getenv("DYLD_SHARED_CACHE_DIR");
		if (dyldSharedRegion && dyldSharedCacheDir && !strcmp(dyldSharedRegion, "private")) {
			// If the local process uses a custom private dsc, use that as the path
			strlcpy(dscPath, dyldSharedCacheDir, PATH_MAX);
			strlcat(dscPath, "/dyld_shared_cache", PATH_MAX);
		}
		else if (!access("/System/Library/Caches/com.apple.dyld", F_OK)) /* iOS <=15 */ {
			strlcpy(dscPath, "/System/Library/Caches/com.apple.dyld/dyld_shared_cache", PATH_MAX);
		}
		else if (!access("/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld", F_OK)) /* iOS >=16 */ {
			strlcpy(dscPath, "/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache", PATH_MAX);
		}

		const char *suffixCandidates[] = {
			"_arm64e",
			"_arm64",
			"_armv7s",
			"_armv7",
		};
		char *rChar = &dscPath[strlen(dscPath)];
		for (int i = 0; i < sizeof(suffixCandidates)/sizeof(*suffixCandidates); i++) {
			*rChar = '\0';
			strlcat(dscPath, suffixCandidates[i], PATH_MAX);
			if (!access(dscPath, F_OK)) {
				break;
			}
		}
		if (access(dscPath, F_OK) != 0) strlcpy(dscPath, "", PATH_MAX);
	});
	return (const char *)dscPath;
}

uintptr_t litehook_get_dsc_slide(void)
{
	static uintptr_t slide = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		task_dyld_info_data_t dyldInfo;
		uint32_t count = TASK_DYLD_INFO_COUNT;
		task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
		struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyldInfo.all_image_info_addr;
		slide = infos->sharedCacheSlide;
	});
	return slide;
}

void *litehook_find_dsc_symbol(const char *imagePath, const char *symbolName)
{
	const char *mainDSCPath = litehook_locate_dsc();
	if (!strlen(mainDSCPath)) return NULL;

	char symbolDSCPath[PATH_MAX];
	strcpy(symbolDSCPath, mainDSCPath);
	strcat(symbolDSCPath, ".symbols");

	void *symbol = NULL;

	FILE *mainDSC = fopen(mainDSCPath, "rb");
	if (!mainDSC) goto end;
	FILE *symbolDSC = fopen(symbolDSCPath, "rb") ?: mainDSC;

	int imageIndex = -1;

	struct dyld_cache_header mainHeader;
	if (fread(&mainHeader, sizeof(mainHeader), 1, mainDSC) != 1) goto end;

	for (int i = 0; i < mainHeader.imagesCount; i++) {
		struct dyld_cache_image_info imageInfo;
		fseek(mainDSC, mainHeader.imagesOffset + sizeof(imageInfo) * i, SEEK_SET);
		if (fread(&imageInfo, sizeof(imageInfo), 1, mainDSC) != 1) goto end;

		char path[PATH_MAX];
		fseek(mainDSC, imageInfo.pathFileOffset, SEEK_SET);
		if (fread(path, PATH_MAX, 1, mainDSC) != 1) goto end;

		if (!strcmp(path, imagePath)) {
			imageIndex = i;
			break;
		}
	}

	struct dyld_cache_header symbolHeader;
	if (fread(&symbolHeader, sizeof(symbolHeader), 1, symbolDSC) != 1) goto end;

	struct dyld_cache_local_symbols_info symbolInfo;
	fseek(symbolDSC, symbolHeader.localSymbolsOffset, SEEK_SET);
	if (fread(&symbolInfo, sizeof(symbolInfo), 1, symbolDSC) != 1) goto end;

	if (imageIndex >= symbolInfo.entriesCount) goto end;

	struct dyld_cache_local_symbols_entry_64 entry;

	if (mainHeader.mappingOffset >= offsetof(struct dyld_cache_header, symbolFileUUID)) {
		// New shared cache, dyld_cache_local_symbols_entry_64
		fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.entriesOffset + (sizeof(entry) * imageIndex), SEEK_SET);
		if (fread(&entry, sizeof(entry), 1, symbolDSC) != 1) goto end;
	}
	else {
		// Old shared cache, dyld_cache_local_symbols_entry
		struct dyld_cache_local_symbols_entry entryOld;
		fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.entriesOffset + (sizeof(entryOld) * imageIndex), SEEK_SET);
		if (fread(&entryOld, sizeof(entryOld), 1, symbolDSC) != 1) goto end;

		// Convert dyld_cache_local_symbols_entry to dyld_cache_local_symbols_entry_64
		entry = (struct dyld_cache_local_symbols_entry_64) {
			.dylibOffset = entryOld.dylibOffset,
			.nlistStartIndex = entryOld.nlistStartIndex,
			.nlistCount = entryOld.nlistCount,
		};
	}

	if ((entry.nlistStartIndex + entry.nlistCount) > symbolInfo.nlistCount) goto end;

	for (uint32_t i = entry.nlistStartIndex; i < entry.nlistStartIndex + entry.nlistCount; i++) {
		struct nlist_64 n;
		fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.nlistOffset + (sizeof(n) * i), SEEK_SET);
		if (fread(&n, sizeof(n), 1, symbolDSC) != 1) goto end;

		fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.stringsOffset + n.n_un.n_strx, SEEK_SET);
		size_t len = _lth_fstrlen(symbolDSC);
		char curSymbolName[len+1];
		if (fread(curSymbolName, len+1, 1, symbolDSC) != 1) goto end;
		if (!strcmp(curSymbolName, symbolName)) {
			symbol = (void *)(litehook_get_dsc_slide() + n.n_value);
		}
	}

end:
	if (mainDSC) {
		if (symbolDSC != mainDSC) {
			fclose(symbolDSC);
		}
		fclose(mainDSC);
	}

	return symbol;
}
