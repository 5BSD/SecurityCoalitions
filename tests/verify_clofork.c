/*
 * Quick test to verify O_CLOFORK behavior with /dev/coalition
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

int main(void)
{
	int fd, flags;
	pid_t pid;
	int status;

	/* Open with O_CLOFORK */
	fd = open("/dev/coalition", O_RDWR | O_CLOFORK);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	printf("Parent: opened /dev/coalition as fd %d\n", fd);

	/* Verify FD_CLOFORK is set */
	flags = fcntl(fd, F_GETFD);
	printf("Parent: F_GETFD = 0x%x (FD_CLOFORK=0x%x, FD_CLOEXEC=0x%x)\n",
	    flags, FD_CLOFORK, FD_CLOEXEC);

	if (!(flags & FD_CLOFORK)) {
		printf("ERROR: FD_CLOFORK not set despite O_CLOFORK!\n");
		close(fd);
		return 1;
	}

	/* Fork child */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return 1;
	}

	if (pid == 0) {
		/* Child: check if fd is valid */
		flags = fcntl(fd, F_GETFD);
		if (flags < 0) {
			printf("Child: fd %d is INVALID (good - O_CLOFORK worked)\n", fd);
			_exit(0);
		} else {
			printf("Child: fd %d is VALID (bad - O_CLOFORK failed!)\n", fd);
			printf("Child: flags = 0x%x\n", flags);
			/* Try to close it - this may crash! */
			printf("Child: attempting close...\n");
			close(fd);
			printf("Child: close succeeded\n");
			_exit(1);
		}
	}

	/* Parent: wait for child */
	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		printf("Parent: child exited with %d\n", WEXITSTATUS(status));
		if (WEXITSTATUS(status) == 0)
			printf("RESULT: O_CLOFORK is working correctly\n");
		else
			printf("RESULT: O_CLOFORK is NOT working!\n");
	} else {
		printf("Parent: child did not exit normally\n");
	}

	close(fd);
	return 0;
}
