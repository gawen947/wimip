/* Copyright (c) 2016, David Hauweele <david@hauweele.net>
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <assert.h>

#include "help.h"
#include "time-substract.h"
#include "safe-call.h"
#include "version.h"
#include "xatoi.h"
#include "scale.h"
#include "af-str.h"
#include "common.h"

#define TRIES       1
#define TIMEOUT     2000             /* default timeout */
#define PAYLOAD_LEN 8                /* default (random) payload len */
#define PAYLOAD_MAX 1024             /* max size for the payload */
#define MESSAGE_MAX 32 + PAYLOAD_MAX /* max len for message buffer */
#define ADDRSTRLEN  MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN) /* max len for address representation */

enum req_flags {
  REQ_RTT      = 0x1, /* measure request RTT */
  REQ_QUIET    = 0x2, /* only display response */
  REQ_AF_INET  = 0x4, /* IPv4 addresses */
  REQ_AF_INET6 = 0x8, /* IPv6 addresses */
};

struct remote {
  const char *port; /* pointer to the port number (just after the host) */
  char host[];      /* null-terminated hostname */
};

static const struct remote * parse_remote(const char *remote)
{
  int remote_len  = strlen(remote);
  struct remote *parsed_remote = xmalloc(sizeof(struct remote) + remote_len);
  const char *port;
  char *brk;

  /* copy the null-terminated remote hostname */
  memset(parsed_remote->host, 0, remote_len + 1);
  memcpy(parsed_remote->host, remote, remote_len);

  /* tokenize the remote and eventually break on the port number */
  strtok_r(parsed_remote->host, ":", &brk);
  port = strtok_r(NULL, ":", &brk);

  if(!port) /* no port specified, we fallback on the default port */
    parsed_remote->port = DEFAULT_PORT_S;
  else
    parsed_remote->port = port;

  /* we are all done!
     the structure shall be freed later by the caller */
  return parsed_remote;
}

static unsigned int sockaddr_addrlen(const struct sockaddr *saddr)
{
  switch(saddr->sa_family) {
  case AF_INET:
    return sizeof(((struct sockaddr_in *)saddr)->sin_addr);
  case AF_INET6:
    return sizeof(((struct sockaddr_in6 *)saddr)->sin6_addr);
  }

  assert(0); /* unsupported address family */
  return 0;
}

static const void * sockaddr_addr(const struct sockaddr *saddr)
{
  switch(saddr->sa_family) {
  case AF_INET:
    return &((struct sockaddr_in *)saddr)->sin_addr;
  case AF_INET6:
    return &((struct sockaddr_in6 *)saddr)->sin6_addr;
  }

  assert(0); /* unsupported address family */
  return 0;
}

static void display_request(const struct addrinfo *resolution,
                            const struct remote *remote,
                            unsigned long flags)
{
  char addrstr[ADDRSTRLEN];

  UNUSED(flags);

  if(remote->port != DEFAULT_PORT_S)
    printf("%s:%s", remote->host, remote->port);
  else
    printf("%s", remote->host);

  /* if we cannot get the representation, we don't display the address
     also we check that the representation is meaningful compared to
     the remote host */
  if(inet_ntop(resolution->ai_family, sockaddr_addr(resolution->ai_addr), addrstr, ADDRSTRLEN) && \
     strcmp(addrstr, remote->host))
    printf(" (%s)", addrstr);

  fputs(": ", stdout);
}

static void display_timeout(const struct addrinfo *resolution,
                            const struct remote *remote,
                            unsigned long flags)
{
  UNUSED(flags);

  display_request(resolution, remote, flags);

  printf("timeout");
}

static int response(const unsigned char *res, unsigned int size,
                    const unsigned char *payload, unsigned int payload_len,
                    const struct addrinfo *resolution, const struct remote *remote,
                    unsigned long flags)
{
  char addrstr[ADDRSTRLEN];
  unsigned int addrlen = sockaddr_addrlen(resolution->ai_addr);

  /* display request info */
  if(!(flags & REQ_QUIET))
    display_request(resolution, remote, flags);

  /* check size, inet_ntop() doesn't */
  if(size != payload_len + addrlen) {
    printf("invalid answer for %s", af_str(resolution->ai_family));
    return -1;
  }

  /* check received payload */
  if(memcmp(payload, res + addrlen, payload_len)) {
    printf("invalid payload");
    return -1;
  }

  if(!inet_ntop(resolution->ai_family, res, addrstr, ADDRSTRLEN)) {
    printf("cannot display address (%s)", strerror(errno));
    return -1;
  }

  /* everything is OK! */
  printf("%s", addrstr);

  return 0;
}

static void display_rtt(struct timespec *begin, struct timespec *end)
{
  uint64_t nsec = substract_nsec(begin, end);
  printf(" => %s", scale_time(nsec));
}

static int send_request(const struct addrinfo *resolution, const struct remote *remote,
                        const unsigned char *payload, unsigned int payload_len,
                        unsigned long flags, unsigned int timeout)
{
  unsigned char message_buffer[MESSAGE_MAX];
  struct timespec begin, end;
  struct timeval tv_timeout;
  ssize_t n;
  int sd;

  sd = socket(resolution->ai_family, SOCK_DGRAM, 0);
  if(sd < 0) {
    warn("cannot create socket");
    return -1;
  }

  /* send datagram */
  clock_gettime(CLOCK_MONOTONIC, &begin);
  n = sendto(sd, payload, payload_len, 0, resolution->ai_addr, resolution->ai_addrlen);
  if(n < 0) {
    warn("cannot send message");
    return -1;
  }

  /* configure timeout limit */
  timeout *= 1000; /* ms to us */
  tv_timeout = (struct timeval){ .tv_sec  = timeout / 1000000,
                                 .tv_usec = timeout % 1000000 };
  setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(struct timeval));

  /* receive response */
  n = read(sd, message_buffer, MESSAGE_MAX);
  if(n < 0) {
    if(errno == EAGAIN) { /* timeout */
      if(!(flags & REQ_QUIET)) {
        display_timeout(resolution, remote, flags);
        putc('\n', stdout);
      }
    }
    else
      warn("network error");
    return -1;
  }
  clock_gettime(CLOCK_MONOTONIC, &end);

  /* process response */
  n = response(message_buffer, n, payload, payload_len, resolution, remote, flags);
  if(n < 0) { /* response() warns */
    putc('\n', stdout);
    return -1;
  }

  /* display RTT (when needed) */
  if(flags & REQ_RTT)
    display_rtt(&begin, &end);

  putc('\n', stdout);

  return 0;
}

static int request(const char *remote, const unsigned char *payload, unsigned int len,
                   unsigned long flags, unsigned int timeout, unsigned int try)
{
  struct addrinfo *resolution, *r;
  struct addrinfo hints;
  const struct remote *parsed_remote = parse_remote(remote);
  int err, ret = -1;

  memset(&hints, 0, sizeof(hints));
  hints = (struct addrinfo){ .ai_family   = AF_UNSPEC,
                             .ai_socktype = SOCK_DGRAM,
                             .ai_flags    = AI_ADDRCONFIG,
                             .ai_protocol = IPPROTO_UDP };

  /* select address family */
  if(flags & REQ_AF_INET)
    hints.ai_family = AF_INET;
  if(flags & REQ_AF_INET6)
    hints.ai_family = AF_INET6;

  err = getaddrinfo(parsed_remote->host, "18768", &hints, &resolution);
  if(err)
    errx(EXIT_FAILURE, "cannot resolve '%s': %s", parsed_remote->host, gai_strerror(err));

  /* send a message to all resolved IPs and break on first success */
  while(try--) {
    for(r = resolution ; r ; r = r->ai_next) {
      err = send_request(r, parsed_remote, payload, len, flags, timeout);

      if(!err) { /* success */
        ret = 0;
        goto EXIT;
      }
    }
  }

EXIT:
  freeaddrinfo(resolution);
  free((void *)parsed_remote);

  return ret;
}

static void print_help(const char *name)
{
  struct opt_help messages[] = {
    { 'h', "help",    "Show this help message" },
    { 'V', "version", "Show version information" },
#ifdef COMMIT
    { 0,   "commit",  "Display commit information" },
#endif /* COMMIT */
    { 't', "rtt",     "Display round-trip-time" },
    { 'n', "try",     "Number of tries" },
    { 'l', "len",     "Random payload length" },
    { 'T', "timeout", "Response timeout" },
    { 'q', "quiet",   "Only display received IPs" },
    { '4', "inet",    "Resolve only IPv4 addresses" },
    { '6', "inet6",   "Resolve only IPv6 addresses" },
    { 0, NULL, NULL }
  };

  help(name, "[OPTIONS] servers...", messages);
}

int main(int argc, char *argv[])
{
  const char    *prog_name;
  unsigned char  payload[PAYLOAD_MAX];
  unsigned long  request_flags = 0;
  unsigned int   payload_len   = PAYLOAD_LEN;
  unsigned int   timeout       = TIMEOUT;
  unsigned int   try           = TRIES;
  int            exit_status   = EXIT_FAILURE;
  int            i, err_atoi;

  enum opt {
    OPT_COMMIT = 0x100
  };

  struct option opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 'V' },
#ifdef COMMIT
    { "commit", no_argument, NULL, OPT_COMMIT },
#endif /* COMMIT */
    { "rtt", no_argument, NULL, 't' },
    { "try", required_argument, NULL, 'n' },
    { "len", required_argument, NULL, 'l' },
    { "timeout", required_argument, NULL, 'T' },
    { "quiet", no_argument, NULL, 'q' },
    { "inet", no_argument, NULL, '4' },
    { "inet6", no_argument, NULL, '6' },
    { NULL, 0, NULL, 0 }
  };

  prog_name = basename(argv[0]);

  while(1) {
    int c = getopt_long(argc, argv, "hVtn:l:T:q46", opts, NULL);

    if(c == -1)
      break;
    switch(c) {
    case 'l':
      payload_len = xatou(optarg, &err_atoi);
      if(err_atoi || payload_len > PAYLOAD_MAX)
        errx(EXIT_FAILURE, "invalid payload length");
      break;
    case 't':
      request_flags |= REQ_RTT;
      break;
    case 'n':
      try = xatou(optarg, &err_atoi);
      if(err_atoi || try == 0)
        err(EXIT_FAILURE, "invalid number of tries");
      break;
    case 'T':
      timeout = xatou(optarg, &err_atoi);
      if(err_atoi || timeout == 0)
        errx(EXIT_FAILURE, "invalid timeout value");
      break;
    case 'q':
      request_flags |= REQ_QUIET;
      break;
    case '4':
      request_flags |= REQ_AF_INET;
      break;
    case '6':
      request_flags |= REQ_AF_INET6;
      break;
    case 'V':
      version(prog_name, "client");
      exit_status = EXIT_SUCCESS;
      goto EXIT;
#ifdef COMMIT
    case OPT_COMMIT:
      commit();
      exit_status = EXIT_SUCCESS;
      goto EXIT;
#endif /* COMMIT */
    case 'h':
      exit_status = EXIT_SUCCESS;
    default:
      print_help(prog_name);
      goto EXIT;
    }
  }

  argc -= optind;
  argv += optind;

  if(argc < 1) {
    print_help(prog_name);
    goto EXIT;
  }

  /* configure payload */
  arc4random_buf(payload, payload_len);

  exit_status = EXIT_SUCCESS;

  /* process the requests from here */
  for(i = 0 ; i < argc ; i++) {
    if(request(argv[i], payload, payload_len, request_flags, timeout, try) < 0)
      exit_status = EXIT_FAILURE;
  }

EXIT:
  exit(exit_status);
}
