#include "litehook.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <mach-o/dyld.h>
#include <dyld_cache_format.h>

uint32_t *test_global = NULL;
void test_function(void)
{
	printf("test\n");
}

const mach_header_u *gMainHeader;
const struct mach_header_u* _NSGetMachExecuteHeader();

int bind_hook(int a1, const struct sockaddr *a2, socklen_t a3)
{
	return 0x42;
}

void test_rebind(void)
{
	litehook_rebind_symbol((mach_header_u*)gMainHeader, bind, bind_hook, NULL);
	if (bind(0, NULL, 0) != 0x42) {
		printf("Failed rebind\n");
		exit(-1);
	}
	else {
		printf("Rebind success!!!\n");
	}
}

void test_symbol_finder(void)
{
	uint32_t **global = litehook_find_symbol(gMainHeader, "_test_global");
	void (*function) = litehook_find_symbol(gMainHeader, "_test_function");

	if ((uint64_t)global != (uint64_t)&test_global) {
		printf("Failed test_global mismatch (%p, expected %p)\n", global, &test_global);
		exit(-1);
	}

	if ((uint64_t)function != (uint64_t)test_function) {
		printf("Failed test_function mismatch (%p, expected %p)\n", function, test_function);
		exit(-1);
	}

	printf("Symbol finder success!!!\n");
}

int main(int argc, const char *argv[])
{
	gMainHeader = (const mach_header_u *)_NSGetMachExecuteHeader();

	test_symbol_finder();
	test_rebind();

	return 0;
}