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
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <assert.h>
#include <err.h>

#include "safe-call.h"
#include "af-str.h"
#include "xatoi.h"
#include "common.h"
#include "help.h"

#define STAT_BUFFER_SIZE 32 /* buffer used to read the stat file */

enum srv_flags {
  SRV_QUIET    = 0x1,  /* stay quiet in daemon mode */
  SRV_AF_INET  = 0x4,  /* listen on IPv4 */
  SRV_AF_INET6 = 0x8,  /* listen on IPv6 */
  SRV_DAEMON   = 0x10, /* detach from terminal */
};

static unsigned long  req_count; /* number of requests */
static unsigned int   af;        /* address family */
static const char    *host;      /* bind host */
static const char    *port;      /* bind port */
static const char    *stat_file; /* file used to store the statistic */

static void save_stat(void)
{
  char buffer[STAT_BUFFER_SIZE];
  int fd;

  /* only save when needed */
  if(!stat_file)
    return;

  fd = xopen(stat_file, O_WRONLY | O_TRUNC | O_CREAT, 0660); /* FIXME: does not report error on syslog */

  memset(buffer, 0, sizeof(buffer));
  snprintf(buffer, STAT_BUFFER_SIZE, "%lu\n", req_count);

  syslog(LOG_INFO, "save stat file");
  xwrite(fd, buffer, strlen(buffer)); /* FIXME: does not report error on syslog */

  close(fd);
}

static void load_stat(void)
{
  char buffer[STAT_BUFFER_SIZE];
  const char *buf;
  int  err_atoi;
  int  fd;

  /* only load when needed */
  if(!stat_file)
    return;

  fd = open(stat_file, O_RDONLY, 0660);
  if(fd < 0) {
    if(errno == ENOENT)
      return; /* do not warn when there is no file */
    syslog(LOG_ERR,   "cannot load stat file"); /* FIXME: what about LOG_PERROR for syslog() ? */
    err(EXIT_FAILURE, "cannot load stat file"); /*        we could avoid using syslog() AND err() */
  }

  memset(buffer, 0, sizeof(buffer));

  syslog(LOG_INFO, "load stat file");
  xread(fd, buffer, STAT_BUFFER_SIZE);
  close(fd); /* close early */

  /* xatou() does not accept whitespaces
     so we trim the buffer before using it */
  buf = trim(buffer, isspace);

  req_count = xatoul(buf, &err_atoi);
  if(err_atoi) {
    syslog(LOG_ERR,    "invalid stat in stat file");
    errx(EXIT_FAILURE, "invalid stat in stat file");
  }
}

static const char * host_name(void)
{
  if(!host) {
    switch(af) {
    case AF_INET:
      return "0.0.0.0";
    case AF_INET6:
      return "::";
    default:
      return "*";
    }
  }

  return host;
}

static const char * port_name(void)
{
  return port;
}

static void log_req_number(void)
{
  syslog(LOG_NOTICE, "%s/%s requests: %lu", host_name(), port_name(), req_count);
  printf("requests: %lu\n", req_count);

  save_stat();
}

static void sig_log(int signum)
{
  UNUSED(signum);

  log_req_number();
}

static void sig_term(int signum)
{
  UNUSED(signum);

  log_req_number();

  syslog(LOG_NOTICE, "exiting...");
  exit(EXIT_SUCCESS);
}

static void setup_siglist(int signals[], struct sigaction *act, int size)
{
  int i;

  sigfillset(&act->sa_mask);
  for(i = 0 ; i < size ; i++)
    sigaction(signals[i], act, NULL);
}

static void setup_signals(void)
{
  struct sigaction act_log  = { .sa_handler = sig_log,  .sa_flags = 0 };
  struct sigaction act_term = { .sa_handler = sig_term, .sa_flags = 0 };

  int signals_log[] = {
    SIGUSR1,
    SIGUSR2 };

  int signals_term[] = {
    SIGHUP,
    SIGINT,
    SIGTERM };

  setup_siglist(signals_log,  &act_log, sizeof_array(signals_log));
  setup_siglist(signals_term, &act_term, sizeof_array(signals_term));
}

#if 0 /* for targets that do not implement daemon() */
static int daemon(int nochdir, int noclose)
{
  int fd;
  switch(fork()) {
  case -1: /* error */
    return -1;
  case 0:  /* child */
    break;
  default: /* parent */
    exit(0);
  }

  if(setsid() == -1)
    return -1;

  if(!nochdir)
    chdir("/");

  if(!noclose && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if(fd > 2)
      close(fd);
  }
  return 0;
}
#endif

static void write_pid(const char *pid_file)
{
  char buf[32];
  int fd = xopen(pid_file, O_WRONLY | O_TRUNC | O_CREAT, 0660);

  sprintf(buf, "%d\n", getpid());

  write(fd, buf, strlen(buf));

  close(fd);
}

static void drop_privileges(const char *user, const char *group)
{
  struct passwd *user_pwd  = getpwnam(user);
  struct group  *group_pwd = getgrnam(group);

  if(!user_pwd)
    errx(EXIT_FAILURE, "invalid user");
  if(!group_pwd)
    errx(EXIT_FAILURE, "invalid group");

  if(setgid(group_pwd->gr_gid) ||
     setuid(user_pwd->pw_uid))
    err(EXIT_FAILURE, "cannot drop privileges");
}

static void answer(int sd, const unsigned char *buffer, ssize_t size,
                   const struct sockaddr *from, socklen_t from_len,
                   unsigned long flags)
{
  unsigned char answer_buffer[ANSWER_MAX];
  unsigned int  len = sockaddr_addrlen(from);
  ssize_t n;

  UNUSED(flags);

  assert(size + len < ANSWER_MAX);

  memcpy(answer_buffer, sockaddr_addr(from), len);
  memcpy(answer_buffer + len, buffer, size);

  n = sendto(sd, answer_buffer, len + size, 0, from, from_len);
  if(n < 0) {
    syslog(LOG_WARNING, "network error: %s", strerror(errno));
    warn("network error");
  }
}

static void server(int sd, unsigned int stat, unsigned long flags)
{
  while(1) {
    struct sockaddr_storage from;
    socklen_t from_len = sizeof(from);
    unsigned char request_buffer[REQUEST_MAX];
    ssize_t n;

  INTR: /* syscall may be interrupted by stats signal (SIGUSR) */
    n = recvfrom(sd, request_buffer, REQUEST_MAX, 0, (struct sockaddr *)&from, &from_len);
    if(n < 0) {
      if(errno == EINTR)
        goto INTR;
      syslog(LOG_ERR, "network error: %s", strerror(errno));
      err(EXIT_FAILURE, "network error");
    }

    answer(sd, request_buffer, n, (struct sockaddr *)&from, from_len, flags);

    req_count++;
    if(stat && !(req_count % stat))
      log_req_number();
  }
}

static void bind_server(unsigned int stat, unsigned long flags)
{
  struct addrinfo *resolution, *r;
  struct addrinfo hints;
  int err, sd;

  memset(&hints, 0, sizeof(hints));
  hints = (struct addrinfo){ .ai_family   = AF_UNSPEC,
                             .ai_socktype = SOCK_DGRAM,
                             .ai_flags    = AI_PASSIVE,
                             .ai_protocol = IPPROTO_UDP };

  /* select address family */
  if(flags & SRV_AF_INET)
    hints.ai_family = AF_INET;
  if(flags & SRV_AF_INET6)
    hints.ai_family = AF_INET6;

  err = getaddrinfo(host, port, &hints, &resolution);
  if(err)
    errx(EXIT_FAILURE, "cannot resolve requested address: %s", gai_strerror(err));

  /* bind to the first working address */
  for(r = resolution ; r ; r = r->ai_next) {
    sd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
    if(sd < 0) {
      warn("cannot create socket %s", af_str(r->ai_family));
      continue;
    }

    err = bind(sd, r->ai_addr, r->ai_addrlen);
    if(err < 0) {
      warn("cannot bind to address");
      close(sd);
      continue;
    }

    /* record address family for printing
       remote host / port in logs */
    af = r->ai_family;

    break;
  }

  if(!r) {
    syslog(LOG_ERR, "cannot bind to any address");
    errx(EXIT_FAILURE, "cannot bind to any address");
  }

  freeaddrinfo(resolution);

  syslog(LOG_INFO, "bind to %s/%s", host_name(), port_name());

  server(sd, stat, flags);
}

static void print_help(const char *name)
{
  struct opt_help messages[] = {
    { 'h', "help",      "Show this help message" },
    { 'V', "version",   "Show version information" },
#ifdef COMMIT
    { 0,   "commit",    "Display commit information" },
#endif /* COMMIT */
    { 'q', "quiet",     "Be quiet in daemon mode" },
    { 'd', "daemon",    "Detach from controlling terminal" },
    { 'U', "user",      "Relinquish privileges" },
    { 'G', "group",     "Relinquish privileges" },
    { 'p', "pid",       "PID file" },
    { 'l', "log-level", "Syslog level from 1 to 8" },
    { 's', "stat",      "Report after specified number of requests"},
    { 'S', "stat-path", "Path to a file that keep track of the stat" },
    { '4', "inet",      "Listen on IPv4 addresses" },
    { '6', "inet6",     "Listen on IPv6 addresses" },
    { 0, NULL, NULL }
  };

  help(name, "[OPTIONS] [host][/port]", messages);
}

int main(int argc, char *argv[])
{
  const char    *prog_name;
  const char    *pid_file     = NULL;
  const char    *user         = NULL;
  const char    *group        = NULL;
  unsigned long  server_flags = 0;
  unsigned int   stat         = 0;
  int            log_level    = LOG_UPTO(LOG_INFO);
  int            exit_status  = EXIT_FAILURE;
  int            err_atoi;

  enum opt {
    OPT_COMMIT = 0x100
  };

  struct option opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 'V' },
#ifdef COMMIT
    { "commit", no_argument, NULL, OPT_COMMIT },
#endif /* COMMIT */
    { "quiet", no_argument, NULL, 'q' },
    { "daemon", no_argument, NULL, 'd' },
    { "user", required_argument, NULL, 'U' },
    { "group", required_argument, NULL, 'G' },
    { "pid", required_argument, NULL, 'p' },
    { "log-level", required_argument, NULL, 'l' },
    { "stat", required_argument, NULL, 's' },
    { "stat-path", required_argument, NULL, 'S' },
    { "inet", no_argument, NULL, '4' },
    { "inet6", no_argument, NULL, '6' },
    { NULL, 0, NULL, 0 }
  };

  prog_name = basename(argv[0]);

  while(1) {
    int c = getopt_long(argc, argv, "hVqdU:G:p:l:s:S:46", opts, NULL);

    if(c == -1)
      break;
    switch(c) {
    case 'q':
      server_flags |= SRV_QUIET;
      break;
    case 'd':
      server_flags |= SRV_DAEMON;
      break;
    case 'U':
      user = optarg;
      break;
    case 'G':
      group = optarg;
      break;
    case 'p':
      pid_file = optarg;
      break;
    case 'l':
      log_level = xatou(optarg, &err_atoi);
      if(err_atoi)
        errx(EXIT_FAILURE, "invalid log level");
      switch(log_level) {
      case 1:
        log_level = LOG_UPTO(LOG_EMERG);
        break;
      case 2:
        log_level = LOG_UPTO(LOG_ALERT);
        break;
      case 3:
        log_level = LOG_UPTO(LOG_CRIT);
        break;
      case 4:
        log_level = LOG_UPTO(LOG_ERR);
        break;
      case 5:
        log_level = LOG_UPTO(LOG_WARNING);
        break;
      case 6:
        log_level = LOG_UPTO(LOG_NOTICE);
        break;
      case 7:
        log_level = LOG_UPTO(LOG_INFO);
        break;
      case 8:
        log_level = LOG_UPTO(LOG_DEBUG);
        break;
      default:
        errx(EXIT_FAILURE, "invalid log level");
      }
      break;
    case 's':
      stat = xatou(optarg, &err_atoi);
      if(err_atoi || stat == 0)
        errx(EXIT_FAILURE, "invalid stat number");
      break;
    case 'S':
      stat_file = optarg;
      /* load stat after opening syslog */
      break;
    case '4':
      server_flags |= SRV_AF_INET;
      break;
    case '6':
      server_flags |= SRV_AF_INET6;
      break;
    case 'V':
      version(prog_name, "server");
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

  /* parse address and port number */
  if(argc == 1) {
    host = strtok(argv[0], "/");
    port = strtok(NULL, "/");
  }
  else if (argc > 1) {
    print_help(prog_name);
    goto EXIT;
  }

  /* some users may use '*' for ADDR_ANY */
  if(host && !strcmp(host, "*"))
    host = NULL;

  /* configure default port */
  if(!port)
    port = DEFAULT_PORT_S;

  /* syslog and start notification */
  openlog(prog_name, LOG_PID, LOG_DAEMON | LOG_LOCAL0);
  setlogmask(log_level);
  syslog(LOG_NOTICE, "%s (%s) from " PACKAGE_VERSION " starting...", prog_name, "server");

  /* daemon mode */
  if(server_flags & SRV_DAEMON) {
    if(daemon(0, !(server_flags & SRV_QUIET)) < 0) {
      syslog(LOG_ERR, "cannot switch to daemon mode: %m");
      err(EXIT_FAILURE, "cannot switch to daemon mode");
    }
    syslog(LOG_INFO, "switched to daemon mode");
  }

  /* setup:
      - write pid
      - drop privileges
      - setup signals
  */
  if(pid_file)
    write_pid(pid_file);

  if(user || group) {
    if(!user || !group)
      errx(EXIT_FAILURE, "user and group required");

    drop_privileges(user, group);
    syslog(LOG_INFO, "drop privileges");
  }

  /* read stat now. we do so after we drop privileges
     since we write the file with lower privileges,
     we must also be able to read it this way. */
  load_stat();

  setup_signals();

  /* start the server now */
  bind_server(stat, server_flags);

EXIT:
  exit(exit_status);
}
