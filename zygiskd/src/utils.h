#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>

#include "constants.h"

#define CONCAT_(x,y) x##y
#define CONCAT(x,y) CONCAT_(x,y)

#define LOGI(...)                                                                          \
  __android_log_print(ANDROID_LOG_INFO, lp_select("zygiskd32", "zygiskd64"), __VA_ARGS__); \
  printf(__VA_ARGS__); \
  FILE *CONCAT(fpl, __LINE__) = fopen("/data/local/tmp/zygiskd.log", "a"); fprintf(CONCAT(fpl, __LINE__), __VA_ARGS__); fclose(CONCAT(fpl, __LINE__))

#define LOGE(...)                                                                           \
  __android_log_print(ANDROID_LOG_INFO , lp_select("zygiskd32", "zygiskd64"), __VA_ARGS__); \
  printf(__VA_ARGS__); \
  FILE *CONCAT(fpl, __LINE__) = fopen("/data/local/tmp/zygiskd.log", "a"); fprintf(CONCAT(fpl, __LINE__), __VA_ARGS__); fclose(CONCAT(fpl, __LINE__))

bool switch_mount_namespace(pid_t pid);

void get_property(const char *name, char *output);

void set_socket_create_context(const char *context);

void unix_datagram_sendto(const char *path, void *buf, size_t len);

int chcon(const char *path, const char *context);

int unix_listener_from_path(char *path);

ssize_t send_fd(int sockfd, int fd);

ssize_t recv_fd(int sockfd, int *fd);

ssize_t write_string(int fd, const char *str);

ssize_t read_string(int fd, char *str, size_t len);

bool exec_command(char *buf, size_t len, const char *file, char *const argv[]);

#endif /* UTILS_H */
