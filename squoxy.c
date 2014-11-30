/*
 * Copyright 2014 Ian Pilcher <arequipeno@gmail.com>
 *
 * This program is free software.  You can redistribute it or modify it under
 * the terms of version 2 of the GNU General Public License (GPL), as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY -- without even the implied warranty of MERCHANTIBILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the text of the GPL for more details.
 *
 * Version 2 of the GNU General Public License is available at:
 *
 *   http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

#define _BSD_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>

#define PIDFILE		"/var/run/squoxy.pid"

static int foreground = 0;

static void log__(int level, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	if (foreground)
		vfprintf(stderr, format, ap);
	else
		vsyslog(level, format, ap);

	va_end(ap);
}

#define STRING__(x)	#x
#define STRINGIFY__(x)	STRING__(x)

#define DEBUG(...)	log__(LOG_DEBUG, "DEBUG: " __FILE__ ":" \
				STRINGIFY__(__LINE__) ": " __VA_ARGS__)

#define INFO(...)	log__(LOG_INFO, "INFO: " __FILE__ ":" \
				STRINGIFY__(__LINE__) ": " __VA_ARGS__)

#define FATAL(...)	do { \
				log__(LOG_ERR, "FATAL: " __FILE__ ":" \
				    STRINGIFY__(__LINE__) ": " __VA_ARGS__ ); \
				exit(EXIT_FAILURE); \
			} while (0)

int main(int argc, char *argv[])
{
	struct sockaddr_in bcast_addr = {
		.sin_family	= AF_INET,
		.sin_port	= htons(3483),
		.sin_addr	= { .s_addr = INADDR_BROADCAST },
	};

	uint8_t buf[1500];

	struct iovec iov = {
		.iov_base	= buf,
		.iov_len	= sizeof buf,
	};

	uint8_t cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];

	struct msghdr mh = {
		.msg_name	= &bcast_addr,
		.msg_namelen	= sizeof bcast_addr,
		.msg_iov	= &iov,
		.msg_iovlen	= 1,
		.msg_control	= cbuf,
		.msg_controllen = sizeof cbuf,
	};

	struct sockaddr_in saddr = {
		.sin_family	= AF_INET,
		.sin_addr	= { .s_addr = INADDR_BROADCAST },
	};

	socklen_t saddr_size;
	struct ifreq ifr = { .ifr_name = { 0 } };
	struct in_pktinfo *pi;
	struct cmsghdr *cmh;
	int listener, sender, one = 1;
	ssize_t n;
	FILE *fp;

	/*
	 * Parse the command line
	 */

	if (argc >= 2 && strcmp(argv[1], "-f") == 0)
		foreground = 1;
	else
		openlog("squoxy", LOG_PID, LOG_DAEMON);

	if (argc != 3 + foreground)
		FATAL("Usage: %s [-f] $src_if $dest_if\n", argv[0]);

	if (strlen(argv[1 + foreground]) >= IFNAMSIZ) {
		FATAL("Source interface name too long: %s\n",
		      argv[1 + foreground]);
	}

	if (strlen(argv[2 + foreground]) >= IFNAMSIZ) {
		FATAL("Destination interface name too long: %s\n",
			argv[2 + foreground]);
	}

	/*
	 * Daemonise
	 */

	if (!foreground) {

		fp = fopen(PIDFILE, "w");
		if (fp == NULL)
			FATAL("fopen(%s, w): %m\n", PIDFILE);

		if (daemon(0, 0) < 0)
			FATAL("daemon: %m\n");

		if (fprintf(fp, "%" PRId64 "\n", (int64_t)getpid()) < 0)
			FATAL("fprintf(" PIDFILE ", ...): %m\n");

		if (fclose(fp) < 0)
			FATAL("fclose(" PIDFILE "): %m\n");
	}

	/*
	 * Create the listener socket
	 */

	listener = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (listener < 0)
		FATAL("Failed to create listener socket: %m\n");

	if (bind(listener, (struct sockaddr *)&saddr, sizeof saddr) < 0)
		FATAL("bind(listener, 255.255.255.255): %m\n");

	if (setsockopt(listener, SOL_SOCKET, SO_BINDTODEVICE,
		       argv[1 + foreground],
		       strlen(argv[1 + foreground]) + 1) < 0) {
		FATAL("setsockopt(listener, SO_BINDTODEVICE, %s): %m\n",
		      argv[1 + foreground]);
	}

	/*
	 * Create the sender socket
	 */

	sender = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (sender < 0)
		FATAL("Failed to create sender socket: %m\n");

	if (setsockopt(sender, IPPROTO_IP, IP_HDRINCL, &one, sizeof one) < 0)
		FATAL("setsockopt(sender, IP_HDRINCL, 1): %m\n");

	if (setsockopt(sender, SOL_SOCKET, SO_BROADCAST, &one, sizeof one) < 0)
		FATAL("setsockopt(sender, SO_BROADCAST, 1): %m\n");

	/*
	 * Create a control message to send broadcasts via the destination
	 * interface
	 */

	strcpy(ifr.ifr_name, argv[2 + foreground]);
	if (ioctl(listener, SIOCGIFINDEX, &ifr) < 0)
		FATAL("ioctl(listener, SIOCGIFINDEX, %s): %m\n", ifr.ifr_name);

	cmh = CMSG_FIRSTHDR(&mh);
	cmh->cmsg_len = CMSG_LEN(sizeof *pi);
	cmh->cmsg_level = SOL_IP;
	cmh->cmsg_type = IP_PKTINFO;
	pi = (struct in_pktinfo *)CMSG_DATA(cmh);
	memset(pi, 0, sizeof *pi);
	pi->ipi_ifindex = ifr.ifr_ifindex;
	mh.msg_controllen = cmh->cmsg_len;

	/*
	 * Do it!
	 */

	INFO("Forwarding Squeezebox discovery broadcasts from %s to %s\n",
	     argv[1 + foreground], argv[2 + foreground]);

	while (1) {

		saddr_size = sizeof saddr;
		n = recvfrom(listener, buf, sizeof buf, 0,
			     (struct sockaddr *)&saddr, &saddr_size);
		if (n < 0)
			FATAL("recvfrom(listener): %m\n");

		if ((buf[0] & 0xf) != 5) {
			DEBUG("Ignoring packet from %s because IHL = %hhd\n",
			      inet_ntoa(saddr.sin_addr), buf[0] & 0xf);
			continue;
		}

		if (ntohs(*(uint16_t *)(buf + 22)) != 3483) {
			DEBUG("Ignoring packet from %s because dest port = "
			       "%hu\n", inet_ntoa(saddr.sin_addr),
			       ntohs(*(uint16_t *)(buf + 22)));
			continue;
		}

		iov.iov_len = n;
		if (sendmsg(sender, &mh, 0) < 0)
			FATAL("sendmsg: %m\n");
	}

	return 0;
}
