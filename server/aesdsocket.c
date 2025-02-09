#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

bool caught_sigint = false;
bool caught_sigterm = false;

static void signal_handler(int signal_number) {
  if (signal_number == SIGINT) {
    printf("Caught SIGINT\n");
    caught_sigint = true;
  } else if (signal_number == SIGTERM) {
    printf("Caught SIGTERM\n");
    caught_sigterm = true;
  }
}

static void register_signal_handler() {
  struct sigaction new_action;
  memset(&new_action, 0, sizeof(new_action));
  new_action.sa_handler = signal_handler;

  if (sigaction(SIGINT, &new_action, NULL) == -1) {
    perror("sigaction");
  }

  if (sigaction(SIGTERM, &new_action, NULL) == -1) {
    perror("sigaction");
  }
}

static void start_daemon() {
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    exit(EXIT_FAILURE);
  }

  if (pid > 0) {
    exit(EXIT_SUCCESS);
  }

  if (setsid() < 0) {
    perror("setsid");
    exit(EXIT_FAILURE);
  }

  umask(0);

  if (chdir("/") < 0) {
    perror("chdir");
    exit(EXIT_FAILURE);
  }

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}

int main(int argc, char *argv[]) {
  const char port[] = "9000";
  const char data_file_name[] = "/var/tmp/aesdsocketdata";
  char ip_address[INET6_ADDRSTRLEN];

  int sockfd;
  int status;
  struct addrinfo hints;
  struct addrinfo *servinfo;
  struct addrinfo *rp;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  status = getaddrinfo(NULL, port, &hints, &servinfo);
  if (status != 0) {
    perror("getaddrinfo");
    return -1;
  }

  for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
    sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sockfd == -1) {
      continue;
    }

    if (bind(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    }

    close(sockfd);
  }

  if (rp != NULL) {
    if (rp->ai_family == AF_INET) {
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
      inet_ntop(rp->ai_family, &(ipv4->sin_addr), ip_address,
                sizeof(ip_address));
    } else if (rp->ai_family == AF_INET6) {
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
      inet_ntop(rp->ai_family, &(ipv6->sin6_addr), ip_address,
                sizeof(ip_address));
    }
  }

  freeaddrinfo(servinfo);

  if (rp == NULL) {
    perror("bind");
    return -1;
  }

  if (argc == 2 && strcmp(argv[1], "-d") == 0) {
    start_daemon();
  } else if (argc > 1) {
    fprintf(stderr, "Invalid arguments\n");
    return -1;
  }

  if (listen(sockfd, 10) == -1) {
    perror("listen");
    return -1;
  }

  register_signal_handler();

  while (!caught_sigint && !caught_sigterm) {
    int acceptedfd;
    struct sockaddr_storage client_addr;
    socklen_t addr_size = sizeof(client_addr);

    acceptedfd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_size);
    if (acceptedfd == -1) {
      if (errno == EINTR) {
        continue;
      }
      perror("accept");
      return -1;
    }

    syslog(LOG_INFO, "Accepted connection from %s", ip_address);

    char buffer[1024];
    ssize_t bytes_read = 0;

    size_t accum_size = 0;
    size_t accum_used = 0;
    char *accum = NULL;

    while (1) {
      bytes_read = recv(acceptedfd, buffer, sizeof(buffer), 0);
      if (bytes_read == -1) {
        perror("recv");
        return -1;
      }
      if (bytes_read == 0) {
        break;
      }

      size_t line_end = 0;
      size_t line_start = 0;

      while (line_end < bytes_read) {
        bool newline_found = false;

        while (++line_end < bytes_read) {
          if (buffer[line_end] == '\n') {
            newline_found = true;
            break;
          }
        }

        size_t line_size = line_end - line_start;
        size_t accum_increase = line_size + 1;

        // Check if the accumulator is large enough
        if (accum_used + accum_increase >= accum_size) {
          accum_size = accum_used + accum_increase;
          char *new_accum = realloc(accum, accum_size);
          if (new_accum == NULL) {
            perror("realloc");
            return -1;
          }
          accum = new_accum;
        }

        // Store the buffer in the accumulator
        memcpy(accum + accum_used, buffer + line_start, line_size);
        accum_used += line_size;

        // Check if the line is complete
        if (newline_found) {
          // Write the line to the data file
          FILE *data_file = fopen(data_file_name, "a");
          fwrite(accum, 1, accum_used, data_file);
          fputc('\n', data_file);
          fclose(data_file);

          // Reset the accumulator
          line_start = line_end + 1;
          accum_used = 0;

          // Send contents of the data file back to the client
          data_file = fopen(data_file_name, "r");
          while (1) {
            size_t bytes_read = fread(buffer, 1, sizeof(buffer), data_file);
            if (bytes_read == 0) {
              break;
            }
            if (send(acceptedfd, buffer, bytes_read, 0) == -1) {
              perror("send");
              return -1;
            }
          }
          fclose(data_file);
        }
      }
    }

    free(accum);
    close(acceptedfd);

    syslog(LOG_INFO, "Closed connection from %s", ip_address);
  }

  syslog(LOG_INFO, "Caught signal, exiting");

  close(sockfd);

  status = unlink(data_file_name);
  if (status == -1) {
    perror("unlink");
    return -1;
  }

  return 0;
}
