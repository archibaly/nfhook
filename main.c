#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main()
{
	int fd = open("/proc/ip_drop", O_RDONLY);
	if (fd < 0) {
		perror("open()");
		return 1;
	}

	char buf[4];
	int n = read(fd, buf, sizeof(buf));
	if (n < 0) {
		close(fd);
		perror("read()");
		return 1;
	}

	buf[n] = '\0';
	printf("%s", buf);
	close(fd);

	return 0;
}
