#ifndef ZN_SOCKET_PROTOCOL_H
#define ZN_SOCKET_PROTOCOL_H

#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

/* INFO: The wire protocol's foundation, and the one copy of it.

         These five were written twice - once in the loader's
         common/socket_utils.c and once in the daemon's src/utils.c - and the two
         copies had already drifted apart: one logged a socket deadline where
         the other said nothing, and each carried its own control-message buffer
         union under its own name. A protocol helper is the worst possible place
         for two answers, because the two ends have to agree byte for byte, and a
         fix applied to one half is a bug in the other half.

         They are static inline in a header for the reason the other shared
         helpers in this tree are: the loader and the daemon are built as
         separate programs, so a shared .c file would have to be linked into
         both, and a header gives each translation unit its own copy.

         None of them log. The caller is the one that knows which exchange
         failed, and every caller in this tree reports it under that name; a
         helper that logs as well turns one failure into two lines saying the
         same thing. EAGAIN is still never retried - see read_loop for why. */

/* INFO: The kernel may copy a struct cmsghdr into the control buffer, so the
         buffer has to be aligned as one instead of being a plain byte array.
         Both ends of a descriptor exchange allocate this, and the sizes have to
         match or the descriptor does not survive the trip. */
union zn_cmsg_buffer {
  struct cmsghdr header;
  char control[CMSG_SPACE(sizeof(int))];
};

static inline ssize_t write_loop(int fd, const void *buf, size_t count) {
  const char *data = (const char *)buf;
  size_t written = 0;

  while (written < count) {
    /* INFO: EAGAIN is not a "try again shortly" here. Every socket that goes
              through write_loop carries SO_SNDTIMEO - rezygiskd_connect sets it,
              and it is cleared again only for the module companion protocols,
              which do not use this path. So EAGAIN means the deadline expired,
              and retrying it in a loop would spin here forever and turn the
              timeout into decoration. */
    ssize_t ret = write(fd, data + written, count - written);
    if (ret == -1) {
      if (errno != EINTR) return -1;

      continue;
    }

    if (ret == 0) return (ssize_t)written;

    written += (size_t)ret;
  }

  return (ssize_t)written;
}

static inline ssize_t read_loop(int fd, void *buf, size_t count) {
  char *data = (char *)buf;
  size_t read_bytes = 0;

  while (read_bytes < count) {
    /* INFO: As in write_loop, EAGAIN means the deadline passed and not "wait and
              retry": the reading sockets carry SO_RCVTIMEO. The monitor's
              non-blocking datagram socket reaches this function too, but it is
              read only after an edge-triggered EPOLLIN, so it either has the
              whole datagram or has hit a permanent error - neither wants a
              retry loop. */
    ssize_t ret = read(fd, data + read_bytes, count - read_bytes);
    if (ret == -1) {
      if (errno != EINTR) return -1;

      continue;
    }

    if (ret == 0) return (ssize_t)read_bytes;

    read_bytes += (size_t)ret;
  }

  return (ssize_t)read_bytes;
}

/* INFO: One descriptor, with the single data byte the peer writes alongside it:
            the payload sizes match on both ends of the exchange. */
static inline ssize_t write_fd(int fd, int sendfd) {
  union zn_cmsg_buffer cmsgbuf;
  char buf[1] = { 0 };

  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof(buf)
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf.control,
    .msg_controllen = sizeof(cmsgbuf.control)
  };

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;

  memcpy(CMSG_DATA(cmsg), &sendfd, sizeof(int));

  return sendmsg(fd, &msg, 0);
}

static inline int read_fd(int fd) {
  union zn_cmsg_buffer cmsgbuf;
  char buf[1] = { 0 };

  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof(buf)
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf.control,
    .msg_controllen = sizeof(cmsgbuf.control)
  };

  ssize_t ret;
  do {
    ret = recvmsg(fd, &msg, MSG_WAITALL);
  } while (ret == -1 && errno == EINTR);

  if (ret == -1) return -1;

  struct cmsghdr *cmsg;
  int sendfd = -1;

  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len < CMSG_LEN(sizeof(int))) continue;

    memcpy(&sendfd, CMSG_DATA(cmsg), sizeof(int));

    break;
  }

  if (sendfd == -1) return -1;

  return sendfd;
}

/* INFO: A length-prefixed string. The length is the byte count that follows,
            not including a terminator, and the receiver is the one that decides
            where it goes - the two ends read and write it differently on
            purpose, the loader allocating and the daemon filling a caller's
            buffer, so only the framing is shared. */
static inline ssize_t write_string(int fd, const char *str) {
  size_t str_len = strlen(str);

  if (write_loop(fd, &str_len, sizeof(size_t)) != (ssize_t)sizeof(size_t)) return -1;

  return write_loop(fd, str, str_len) == (ssize_t)str_len ? (ssize_t)str_len : -1;
}

#endif /* ZN_SOCKET_PROTOCOL_H */
