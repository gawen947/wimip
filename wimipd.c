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
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <err.h>

#include "safe-call.h"
#include "xatoi.h"
#include "common.h"
#include "help.h"

enum srv_flags {
  SRV_QUIET    = 0x1,  /* stay quiet in daemon mode */
  SRV_AF_INET  = 0x4,  /* listen on IPv4 */
  SRV_AF_INET6 = 0x8,  /* listen on IPv6 */
  SRV_DAEMON   = 0x10, /* detach from terminal */
};

static unsigned long  req_count; /* number of requests */
static const char    *host_name;
static const char    *port_name;

static void log_req_number(void)
{
  syslog(LOG_INFO, "%s:%s requests: %lu", host_name, port_name, req_count);
}

static void sig_log(int signum)
{
  UNUSED(signum);

  log_req_number();
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
  struct sigaction act_log = { .sa_handler = sig_log, .sa_flags = 0 };

  int signals_log[] = {
    SIGUSR1,
    SIGUSR2 };

  setup_siglist(signals_log, &act_log, sizeof_array(signals_log));
}

//#if !(defined _BSD_SOURCE || (defined _XOPEN_SOURCE && defined _XOPEN_SOURCE > 500))
#if 0
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
  int fd = xopen(pid_file, O_WRONLY | O_TRUNC | O_CREAT, 0);

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
    { 'l', "log-level", "Syslog level from 1 to 7" },
    { 'L', "log",       "Report after specified number of requests"},
    { '4', "inet",      "Listen on IPv4 addresses" },
    { '6', "inet6",     "Listen on IPv6 addresses" },
    { 0, NULL, NULL }
  };

  help(name, "[OPTIONS] [host][:port]", messages);
}

int main(int argc, char *argv[])
{
  const char    *prog_name;
  const char    *pid_file;
  const char    *host         = NULL;
  const char    *port         = DEFAULT_PORT_S;
  const char    *user         = NULL;
  const char    *group        = NULL;
  unsigned long  server_flags = 0;
  unsigned int   log_level    = LOG_UPTO(LOG_NOTICE);
  unsigned int   log          = 0;
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
    { "log", required_argument, NULL, 'L' },
    { "inet", no_argument, NULL, '4' },
    { "inet6", no_argument, NULL, '6' },
    { NULL, 0, NULL, 0 }
  };

  prog_name = basename(argv[0]);

  while(1) {
    int c = getopt_long(argc, argv, "hVqdU:G:p:l:L:46", opts, NULL);

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
    case 'L':
      log = xatou(optarg, &err_atoi);
      if(err_atoi || log == 0)
        errx(EXIT_FAILURE, "invalid log number");
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
    host = strtok(argv[0], ":");
    port = strtok(NULL, ":");
  }
  else if (argc > 1) {
    print_help(prog_name);
    goto EXIT;
  }

  /* display bind in syslog */
  host_name = host;
  port_name = port;
  if(!host)
    host_name = "*";

  /* syslog */
  setlogmask(log_level);
  openlog(prog_name, LOG_CONS | LOG_NDELAY, LOG_DAEMON | LOG_LOCAL1);

  /* start notification */
  syslog(LOG_NOTICE, PACKAGE " v" PACKAGE_VERSION " starting...");

  /* daemon mode */
  if(server_flags & SRV_DAEMON) {
    if(daemon(0, !(server_flags & SRV_QUIET)) < 0) {
      syslog(LOG_ERR, "cannot switch to daemon mode: %m");
      err(EXIT_FAILURE, "cannot switch to daemon mode");
    }
    syslog(LOG_INFO, "switched to daemon mode");
  }

  if(pid_file)
    write_pid(pid_file);

  if(user || group) {
    if(!user || !group)
      errx(EXIT_FAILURE, "user and group required");

    drop_privileges(user, group);
  }

  /* TODO: drop privileges */

  setup_signals();
EXIT:
  exit(exit_status);
}
