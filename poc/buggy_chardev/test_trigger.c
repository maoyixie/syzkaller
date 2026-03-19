// Manual test to trigger the buggy_chardev logic bug.
// Compile: gcc -o test_trigger test_trigger.c
// Run: ./test_trigger (after loading buggy_chardev.ko)
// Expected: read() returns 4096 when only 16 bytes were requested.

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(void)
{
	int fd = open("/dev/buggy_chardev", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	// Large buffer to safely receive data, but only REQUEST 16 bytes.
	// The buggy driver ignores count and writes 4096 bytes anyway.
	char buf[8192];
	size_t request_count = 16;
	ssize_t ret = read(fd, buf, request_count);
	printf("read(fd, buf, %zu) = %zd\n", request_count, ret);

	if (ret > (ssize_t)request_count)
		printf("LOGIC BUG DETECTED: read returned %zd > count %zu\n", ret, request_count);
	else
		printf("No bug detected (ret <= count)\n");

	close(fd);
	return 0;
}
