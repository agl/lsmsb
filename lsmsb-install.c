#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int
usage(const char *argv0) {
  fprintf(stderr, "Usage: %s <sandbox file>\n", argv0);
  return 1;
}

int
main(int argc, char **argv) {
  if (argc != 2)
    return usage(argv[0]);

  const int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror("opening input");
    return 1;
  }

  struct stat st;
  fstat(fd, &st);

  uint8_t *buffer = malloc(st.st_size);
  read(fd, buffer, st.st_size);

  const int sandboxfd = open("/proc/self/sandbox", O_WRONLY);
  if (sandboxfd < 0) {
    perror("Opening /proc/self/sandbox");
    return 1;
  }

  if (write(sandboxfd, buffer, st.st_size) == -1) {
    perror("Installing sandbox");
    return 1;
  }

  fprintf(stderr, "Sandbox installed\n");

  execl("/bin/bash", "/bin/bash", NULL);

  return 127;
}