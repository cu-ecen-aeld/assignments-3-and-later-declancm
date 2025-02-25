#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

struct aesd_seekto {
    uint32_t write_cmd;
    uint32_t write_cmd_offset;
};

#define AESD_IOC_MAGIC 0x16
#define AESDCHAR_IOCSEEKTO _IOWR(AESD_IOC_MAGIC, 1, struct aesd_seekto)

struct connection_data {
  pthread_t pid;
  int sockfd;
  char ip_address[INET6_ADDRSTRLEN];
  bool completed;
  SLIST_ENTRY(connection_data) entries;
};

SLIST_HEAD(slisthead, connection_data);

const char port[] = "9000";
#if USE_AESD_CHAR_DEVICE
const char data_file_name[] = "/dev/aesdchar";
#else
const char data_file_name[] = "/var/tmp/aesdsocketdata";
#endif

bool caught_alarm = false;
bool caught_sigint = false;
bool caught_sigterm = false;

pthread_mutex_t data_file_mutex = PTHREAD_MUTEX_INITIALIZER;

static void signal_handler(int signal_number) {
  if (signal_number == SIGALRM) {
    caught_alarm = true;
  } else if (signal_number == SIGINT) {
    caught_sigint = true;
  } else if (signal_number == SIGTERM) {
    caught_sigterm = true;
  }
}

static void register_signal_handler() {
  struct sigaction new_action;
  memset(&new_action, 0, sizeof(new_action));
  new_action.sa_handler = signal_handler;

  if (sigaction(SIGALRM, &new_action, NULL) == -1) {
    perror("sigaction");
  }

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

static void write_to_data_file(const char *line) {
  pthread_mutex_lock(&data_file_mutex);

  FILE *data_file = fopen(data_file_name, "a");

  if (data_file == NULL) {
    perror("fopen");
  } else {
    fprintf(data_file, "%s\n", line);
    fclose(data_file);
  }

  pthread_mutex_unlock(&data_file_mutex);
}

static void send_seek(unsigned int write_cmd, unsigned int write_cmd_offset) {
  pthread_mutex_lock(&data_file_mutex);

  int fd = open(data_file_name, O_RDWR);

  if (fd == -1) {
    perror("fopen");
  } else {
    struct aesd_seekto seekto = {
      .write_cmd = write_cmd,
      .write_cmd_offset = write_cmd_offset,
    };

    if (ioctl(fd, AESDCHAR_IOCSEEKTO, &seekto) == -1) {
      perror("ioctl");
    }
    close(fd);
  }

  pthread_mutex_unlock(&data_file_mutex);
}

static void send_data_file(int sockfd) {
  pthread_mutex_lock(&data_file_mutex);

  FILE *data_file = fopen(data_file_name, "rb");

  if (data_file == NULL) {
    perror("fopen");
  } else {
    char buffer[1024];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), data_file)) > 0) {
      if (send(sockfd, buffer, bytes_read, 0) < 0) {
        perror("Failed to send file");
        break;
      }
    }

    fclose(data_file);
  }

  pthread_mutex_unlock(&data_file_mutex);
}

static void start_timer() {
  const long interval = 10;

  struct itimerval timer;
  timer.it_value.tv_sec = interval;
  timer.it_value.tv_usec = 0;
  timer.it_interval.tv_sec = interval;
  timer.it_interval.tv_usec = 0;

  setitimer(ITIMER_REAL, &timer, NULL);
}

static void write_time_to_data() {
  time_t time_raw;
  struct tm time_info;
  char time_string[80];

  time(&time_raw);
  localtime_r(&time_raw, &time_info);

  strftime(time_string, sizeof(time_string), "timestamp:%a, %d %b %Y %T %z",
           &time_info);
  write_to_data_file(time_string);
}

static void send_and_receive(struct connection_data *data) {
  char buffer[1024];
  ssize_t bytes_read = 0;

  char *accum = NULL;
  size_t accum_size = 0;
  size_t accum_used = 0;

  syslog(LOG_INFO, "Accepted connection from %s", data->ip_address);

  while (1) {
    bytes_read = recv(data->sockfd, buffer, sizeof(buffer), 0);
    if (bytes_read == -1) {
      perror("recv");
      break;
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
          break;
        }
        accum = new_accum;
      }

      // Store the buffer in the accumulator
      memcpy(accum + accum_used, buffer + line_start, line_size);
      accum_used += line_size;

      if (newline_found) {
        accum[accum_used] = '\0';
        unsigned int write_cmd;
        unsigned int write_cmd_offset;

        if (sscanf(accum, "AESDCHAR_IOCSEEKTO:%u,%u", &write_cmd, &write_cmd_offset) == 2) {
          send_seek(write_cmd, write_cmd_offset);
        } else {
          write_to_data_file(accum);
        }
        send_data_file(data->sockfd);

        // Reset the accumulator
        line_start = line_end + 1;
        accum_used = 0;
      }
    }
  }

  free(accum);
  close(data->sockfd);

  syslog(LOG_INFO, "Closed connection from %s", data->ip_address);

  data->completed = true;
}

int main(int argc, char *argv[]) {
  int sockfd;
  int status;
  struct addrinfo hints;
  struct addrinfo *servinfo;
  struct addrinfo *rp;
  struct connection_data *data;

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
  
#if !USE_AESD_CHAR_DEVICE
  start_timer();
#endif

  struct slisthead head;
  SLIST_INIT(&head);

  while (!caught_sigint && !caught_sigterm) {
    int clientfd;
    struct sockaddr_storage client_addr;
    socklen_t addr_size = sizeof(client_addr);

    if (caught_alarm) {
      write_time_to_data();
      caught_alarm = false;
    }

    clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_size);
    if (clientfd == -1) {
      if (errno == EINTR) {
        continue;
      }
      perror("accept");
      return -1;
    }

    data = malloc(sizeof(struct connection_data));

    if (data == NULL) {
      perror("malloc");
      continue;
    }

    if (client_addr.ss_family == AF_INET) {
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)&client_addr;
      inet_ntop(AF_INET, &(ipv4->sin_addr), data->ip_address, INET_ADDRSTRLEN);
    } else {
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&client_addr;
      inet_ntop(AF_INET6, &(ipv6->sin6_addr), data->ip_address,
                INET6_ADDRSTRLEN);
    }

    data->sockfd = clientfd;
    data->completed = false;
    pthread_create(&data->pid, NULL, (void *)&send_and_receive, data);

    if (data->pid == -1) {
      perror("pthread_create");
      free(data);
      continue;
    }

    SLIST_INSERT_HEAD(&head, data, entries);

    struct connection_data *next;
    data = SLIST_FIRST(&head);
    while (data != NULL) {
      next = SLIST_NEXT(data, entries);
      if (data->completed) {
        SLIST_REMOVE(&head, data, connection_data, entries);
        pthread_join(data->pid, NULL);
        free(data);
      }
      data = next;
    }
  }

  while (!SLIST_EMPTY(&head)) {
    data = SLIST_FIRST(&head);
    SLIST_REMOVE_HEAD(&head, entries);
    pthread_join(data->pid, NULL);
    free(data);
  }
  SLIST_INIT(&head);

  syslog(LOG_INFO, "Caught signal, exiting");

  close(sockfd);

#if !USE_AESD_CHAR_DEVICE
  status = unlink(data_file_name);
  if (status == -1) {
    perror("unlink");
    return -1;
  }
#endif

  return 0;
}
