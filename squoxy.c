/*
 * Copyright 2014, 2017 Ian Pilcher <arequipeno@gmail.com>
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

#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <syslog.h>
#include <poll.h>

#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>

/* Magic numbers */
#define	SSDP_INADDR		0xeffffffa	/* 239.255.255.250 */
#define SSDP_PORT		1900
#define SQUEEZEBOX_PORT		3483
#define UE_RADIO_PORT		3546

/* Discovery packets shouldn't even be this large */
#define PKTBUF_SIZE		2000


/*
 * Macro versions of htons() and htonl() for static initializers and literals
 */

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

#define HTONS(x)	(x)
#define HTONL(x)	(x)

#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

#define HTONS(x)	((((x) & 0x00ff) << 8) | (((x) & 0xff00) >> 8))
#define HTONL(x)	((((x) & 0x000000ff) << 24)		\
				| (((x) & 0x0000ff00) << 8)	\
				| (((x) & 0x00ff0000) >> 8)	\
				| (((x) & 0xff000000) >> 24))

#else

#error "__BYTE_ORDER__ is not __ORDER_BIG_ENDIAN__ or __ORDER_LITTLE_ENDIAN__"

#endif


/*
 * Command-line options
 */

static _Bool use_syslog = 1;
static unsigned verbosity = LOG_NOTICE;
static _Bool enforce_udp_cksum = 1;


/*
 * Logging
 */

static void log__(int level, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	if (!use_syslog)
		vfprintf(stderr, format, ap);
	else
		vsyslog(level, format, ap);

	va_end(ap);
}

#define STRING__(x)	#x
#define STRINGIFY__(x)	STRING__(x)

/* Log DEBUG messages (if enabled) at LOG_INFO, so syslog doesn't drop them */
#define DEBUG(...)	do { \
				if (verbosity == LOG_DEBUG) { \
					log__(LOG_INFO, "DEBUG: " __FILE__ ":" \
					      STRINGIFY__(__LINE__) ": " \
					      __VA_ARGS__); \
				} \
			} while (0)


#define INFO(...)	do { \
				if (verbosity >= LOG_INFO) { \
					log__(LOG_INFO, "INFO: " __FILE__ ":" \
					      STRINGIFY__(__LINE__) ": " \
					      __VA_ARGS__); \
				} \
			} while (0)

#define NOTICE(...)	log__(LOG_NOTICE, "NOTICE: " __FILE__ ":" \
			      STRINGIFY__(__LINE__) ": " __VA_ARGS__)

#define WARN(...)	log__(LOG_WARNING, "WARNING: " __FILE__ ":" \
			      STRINGIFY__(__LINE__) ": " __VA_ARGS__)

#define ERROR(...)	log__(LOG_ERR, "ERROR: " __FILE__ ":" \
			      STRINGIFY__(__LINE__) ": " __VA_ARGS__)

#define FATAL(...)	do { \
				log__(LOG_CRIT, "FATAL: " __FILE__ ":" \
				      STRINGIFY__(__LINE__) ": " __VA_ARGS__); \
				exit(EXIT_FAILURE); \
			} while (0)


/*
 * Structures for IPv4 and UDP headers
 */

struct ip4_hdr {
/* GCC bitfield order depends on endianness */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint8_t		version:4;
	uint8_t		ihl:4;
#else
	uint8_t		ihl:4;
	uint8_t		version:4;
#endif
	uint8_t		tos;			/* DSCP and ECN */
	uint16_t	total_length;
	uint16_t	identification;
	uint16_t	frag;			/* fragment offset and flags */
	uint8_t		ttl;
	uint8_t		protocol;
	uint16_t	hdr_cksum;
	struct in_addr	source_addr;
	struct in_addr	dest_addr;
};

struct udp_hdr {
	uint16_t	source_port;
	uint16_t	dest_port;
	uint16_t	length;
	uint16_t	checksum;
};

/* Ensure structures are packed */
_Static_assert(sizeof(struct ip4_hdr) == 20, "struct ip4_hdr size");
_Static_assert(sizeof(struct udp_hdr) == 8, "struct upd_hdr size");


/*
 * Shared data for sending & receiving packets
 */

/* .sin_addr will be copied from packet being sent */
static struct sockaddr_in send_addr = {
	.sin_family	= AF_INET,
	.sin_port	= IPPROTO_UDP
};

static union {
	struct ip4_hdr	hdr;
	uint8_t		buf[PKTBUF_SIZE];
} pktbuf;

/* .iov_len will be set to packet size */
static struct iovec iov = {
	.iov_base	= pktbuf.buf
};

/* sendmsg "control information" - used to send via specific interface */
static uint8_t cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];

static const struct msghdr mh = {
	.msg_name	= &send_addr,
	.msg_namelen	= sizeof send_addr,
	.msg_iov	= &iov,
	.msg_iovlen	= 1,
	.msg_control	= cmsg_buf,
	.msg_controllen	= CMSG_LEN(sizeof(struct in_pktinfo))
};


/*
 * Parse command line
 */

/* Logging macros only work with literal format strings */
#define VERB_ERROR	"Verbosity (-d or -i) specified more than once\n"
#define USAGE_MSG	"Usage: %s {-h} [-f] [-d|-i] [-U] LISTEN_IF SEND_IF\n"

static unsigned parse_args(int argc, char *argv[])
{
	unsigned num_opts;
	int i;

	if (argc >= 2 && strcmp(argv[1], "-h") == 0)
		goto show_help;

	if (argc < 3)
		FATAL(USAGE_MSG, argv[0]);

	for (i = 1, num_opts = 0; i < argc - 2; ++i) {

		if (strcmp(argv[i], "-f") == 0) {
			if (use_syslog == 0)
				FATAL("Duplicate option: %s\n", argv[i]);
			use_syslog = 0;
			++num_opts;
		}
		else if (strcmp(argv[i], "-d") == 0) {
			if (verbosity != LOG_NOTICE)
				FATAL(VERB_ERROR);
			verbosity = LOG_DEBUG;
			++num_opts;
		}
		else if (strcmp(argv[i], "-i") == 0) {
			if (verbosity != LOG_NOTICE)
				FATAL(VERB_ERROR);
			verbosity = LOG_INFO;
			++num_opts;
		}
		else if (strcmp(argv[i], "-L") == 0) {
			if (enforce_udp_cksum == 0)
				FATAL("Lax (-L) specified more than once\n");
			enforce_udp_cksum = 0;
			++num_opts;
		}
		else if (strcmp(argv[i], "-h") == 0) {
			goto show_help;
		}
		else {
			if (!use_syslog)
				NOTICE(USAGE_MSG, argv[0]);
			FATAL("Invalid option: %s\n", argv[i]);
		}
	}

	return num_opts;

show_help:
	printf(USAGE_MSG, argv[0]);
	puts("\t-h\thelp: show this message");
	puts("\t-f\tforeground: log to stderr instead of syslog");
	puts("\t-d\tdebug: log debug (and info) messages");
	puts("\t-i\tinfo: log info messages");
	puts("\t-L\tlax: forward packets that don't have a UDP checksum");
	exit(EXIT_SUCCESS);
}


/*
 * Socket setup
 */

/* Convenience type to avoid casts */
union sockaddr_x {
	struct sockaddr		sa;
	struct sockaddr_in	sin;
};

/* Broadcast listener listens for broadcast UDP packets to *any* port (subject
 * to iptables) */
static int setup_bcast_listener(const char *const if_name)
{
	const union sockaddr_x listen_addr = {
		.sin = {
			.sin_family	= AF_INET,
			.sin_port	= 0,
			.sin_addr	= { INADDR_BROADCAST }
		}
	};

	int fd;

	fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP);
	if (fd < 0)
		FATAL("Failed to create broadcast listener: %m\n");

	if (bind(fd, &listen_addr.sa, sizeof listen_addr.sin) < 0) {
		FATAL("Failed to bind broadcast listener to address "
		      "(255.255.255.255): %m\n");
	}

	if (setsockopt(fd, SOL_SOCKET,
		       SO_BINDTODEVICE, if_name, strlen(if_name) + 1) < 0) {
		FATAL("Failed to bind broadcast listener to interface "
		      "(%s): %m\n",
		      if_name);
	}

	return fd;
}

/* Multicast listener listens for UDP packets to 239.255.255.250:1900 */
static int setup_mcast_listener(const char *const if_name)
{
	const union sockaddr_x listen_addr = {
		.sin = {
			.sin_family	= AF_INET,
			.sin_port	= HTONS(SSDP_PORT),
			.sin_addr	= { HTONL(SSDP_INADDR) }
		}
	};

	struct ip_mreq imr;
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP);
	if (fd < 0)
		FATAL("Failed to create multicast listener: %m\n");

	if (bind(fd, &listen_addr.sa, sizeof listen_addr.sin) < 0) {
		FATAL("Failed to bind multicast listener to address "
		      "(239.255.255.250:1900): %m\n");
	}

	memset(ifr.ifr_name, 0, IFNAMSIZ);
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
	ifr.ifr_addr.sa_family = AF_INET;

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
		FATAL("Failed to get IPv4 address of %s: %m\n", if_name);

	imr.imr_interface = ((struct sockaddr_in *)(&ifr.ifr_addr))->sin_addr;
	imr.imr_multiaddr.s_addr = HTONL(SSDP_INADDR);

	if (setsockopt(fd, IPPROTO_IP,
		       IP_ADD_MEMBERSHIP, &imr, sizeof imr) < 0) {
		FATAL("Failed to bind multicast listener to interface "
		      "(%s): %m\n",
		      if_name);
	}

	return fd;
}

/* Creates sender socket and sets up control information */
static int setup_sender(const char *const if_name)
{
	struct in_pktinfo *ipi;
	struct cmsghdr *cmh;
	struct ifreq ifr;
	int fd, opt;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (fd < 0)
		FATAL("Failed to create sender socket: %m\n");

	opt = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof opt) < 0)
		FATAL("Failed to configure sender socket (IP_HDRINCL): %m\n");

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof opt) < 0)
		FATAL("Failed to configure sender socket (SO_BROADCAST): %m\n");

	memset(ifr.ifr_name, 0, sizeof ifr.ifr_name);
	strncpy(ifr.ifr_name, if_name, sizeof ifr.ifr_name - 1);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
		FATAL("Failed to get interface index of %s: %m\n", if_name);

	cmh = CMSG_FIRSTHDR(&mh);
	cmh->cmsg_len = CMSG_LEN(sizeof *ipi);
	cmh->cmsg_level = SOL_IP;
	cmh->cmsg_type = IP_PKTINFO;

	ipi = (struct in_pktinfo *)CMSG_DATA(cmh);
	memset(ipi, 0, sizeof *ipi);
	ipi->ipi_ifindex = ifr.ifr_ifindex;

	return fd;
}


/*
 * Logging helpers for packet validation and processing
 */

/* buf must hold at least INET_ADDRSTRLEN characters */
static const char *ntoa(const struct in_addr in, char *const buf)
{
	if (inet_ntop(AF_INET, &in, buf, INET_ADDRSTRLEN) == NULL)
		FATAL("Failed to format IPv4 address: %m\n");

	return buf;
}

/* Buffer for ip_from_to and udp_from_to */
static char from_to_buf[] =
			"from XXX.XXX.XXX.XXX:XXXXX to YYY.YYY.YYY.YYY:YYYYY";

/* Format "from XXX.XXX.XXX.XXX to YYY.YYY.YYY.YYY" */
static const char *ip_from_to(void)
{
	char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];

	if (sprintf(from_to_buf, "from %s to %s",
		    ntoa(pktbuf.hdr.source_addr, sbuf),
		    ntoa(pktbuf.hdr.dest_addr, dbuf)) < 0)
		FATAL("sprintf: %m\n");

	return from_to_buf;
}

/* Format "from XXX.XXX.XXX.XXX:XXXXX to YYY.YYY.YYY.YYY:YYYYY" */
static const char *udp_from_to(const struct udp_hdr *const udp)
{
	char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];

	if (sprintf(from_to_buf, "from %s:%" PRIu16 " to %s:%" PRIu16,
		    ntoa(pktbuf.hdr.source_addr, sbuf), ntohs(udp->source_port),
		    ntoa(pktbuf.hdr.dest_addr, dbuf), ntohs(udp->dest_port))
		< 0) {

		FATAL("sprintf: %m\n");
	}

	return from_to_buf;
}


/*
 * Packet validation
 */

/* Returned in host byte order; don't call until IHL is validated */
static uint16_t ip4_hdr_cksum(void)
{
	const uint16_t *const words = (uint16_t *)pktbuf.buf;

	uint32_t sum;
	unsigned i;

	/* IHL is 32-bit dwords, so double it to get number of 16-bit words */
	for (sum = 0, i = 0; i < pktbuf.hdr.ihl * 2u; ++i) {

		if (i != offsetof(struct ip4_hdr, hdr_cksum) / sizeof *words)
			sum += ntohs(words[i]);
	}

	while (sum & 0xffff0000)
		sum = (sum & 0x0000ffff) + (sum >> 16);

	return ~(uint16_t)sum;
}

/* Returned in host byte order; don't call until UDP length is validated */
static uint16_t udp_cksum(const struct udp_hdr *const udp)
{
	uint16_t udp_length;
	uint16_t *words;
	uint32_t sum;
	unsigned i;

	/*
	 * IPv4 "pseudo header
	 */

	/* First 4 words of the pseudo header are source & dest addresses */
	words = (uint16_t *)&pktbuf.hdr.source_addr;
	for (sum = 0, i = 0; i < 4; ++i)
		sum += ntohs(words[i]);

	/* Next word is "zeroes" and protocol (0x0011 in network byte order) */
	sum += 0x011;

	/* Next word is "UDP length" (same as length in UDP header) */
	udp_length = ntohs(udp->length);
	sum += udp_length;

	/*
	 * UDP header & data
	 */

	_Static_assert(sizeof pktbuf.buf % 2 == 0, "odd size pktbuf");
	if (udp_length % 2)
		((uint8_t *)udp)[udp_length] = 0;

	words = (uint16_t *)udp;

	for (i = 0; i < (udp_length + 1u) / 2u; ++i) {

		if (i != offsetof(struct udp_hdr, checksum) / sizeof *words)
			sum += htons(words[i]);
	}

	while (sum & 0xffff0000)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~(uint16_t)sum;
}

/* Sanity check a packet and find its UDP header */
struct udp_hdr *check_packet(size_t pkt_size)
{
	struct udp_hdr *udp;

	if (pkt_size == PKTBUF_SIZE
			&& ntohs(pktbuf.hdr.total_length) > PKTBUF_SIZE) {
		WARN("%" PRIu16 " byte packet %s was truncated\n",
		     ntohs(pktbuf.hdr.total_length), ip_from_to());
		return NULL;
	}

	if (ntohs(pktbuf.hdr.total_length) != pkt_size) {
		WARN("Packet %s claims to be %" PRIu16 " bytes; "
		     "received %zd bytes\n",
		     ip_from_to(), ntohs(pktbuf.hdr.total_length), pkt_size);
		return NULL;
	}

	/* Yes, this is a joke, but what the heck */
	if (ntohs(pktbuf.hdr.frag) & 0x8000) {
		WARN("EVIL packet %s\n", ip_from_to());
		return NULL;
	}

	if (pktbuf.hdr.ihl < 5) {
		WARN("Packet %s has invalid IHL (%" PRIu8 ")\n",
		     ip_from_to(), pktbuf.hdr.ihl);
		return NULL;
	}

	if (ntohs(pktbuf.hdr.hdr_cksum) != ip4_hdr_cksum()) {
		WARN("Invalid IPv4 header checksum in packet %s\n",
		     ip_from_to());
		return NULL;
	}

	/* If "more fragments" flag is set or fragment offset is non-zero */
	if (ntohs(pktbuf.hdr.frag) & 0x3fff) {
		INFO("Ignoring packet fragment %s\n", ip_from_to());
		return NULL;
	}

	if (pktbuf.hdr.protocol != IPPROTO_UDP) {
		INFO("Ignoring non-UDP packet %s\n", ip_from_to());
		return NULL;
	}

	if (pktbuf.hdr.ihl * 4 + sizeof *udp > pkt_size) {
		WARN("IHL (%" PRIu8 ") "
		     "places end of UDP header outside %zd byte packet %s\n",
		     pktbuf.hdr.ihl, pkt_size, ip_from_to());
		return NULL;
	}

	udp = (struct udp_hdr *)(pktbuf.buf + pktbuf.hdr.ihl * 4);

	if (pktbuf.hdr.ihl * 4u + ntohs(udp->length) != pkt_size) {
		WARN("UDP length (%" PRIu16 ") does not match ",
		     "%zd byte packet %s (IHL = %" PRIu8 ")\n",
		     ntohs(udp->length), pkt_size,
		     udp_from_to(udp), pktbuf.hdr.ihl);
		return NULL;
	}

	if (udp->checksum == 0) {

		if (enforce_udp_cksum) {
			INFO("Ignoring packet %s without UDP checksum\n",
			     udp_from_to(udp));
			return NULL;
		}
		else {
			DEBUG("Forwarding packet %s without UDP checksum\n",
			      udp_from_to(udp));
		}
	}
	else {
		if (ntohs(udp->checksum) != udp_cksum(udp)) {
			WARN("Invalid UDP checksum in packet %s\n",
			     udp_from_to(udp));
			return NULL;
		}
	}

	return udp;
}


/*
 * Process a packet
 */

static void process_packet(int listener, int sender, const char *const ltype)
{
	const struct udp_hdr *udp;
	union sockaddr_x from;
	socklen_t from_size;
	ssize_t pkt_size;

	from_size = sizeof from;
	pkt_size = recvfrom(listener, pktbuf.buf, sizeof pktbuf.buf, 0,
			    &from.sa, &from_size);
	if (pkt_size < 0) {

		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			DEBUG("Spurious wakeup on %s listener\n", ltype);
			return;
		}

		FATAL("Failed to read packet from %s listener: %m\n", ltype);
	}

	udp = check_packet(pkt_size);
	if (udp == NULL)
		return;

	if (pktbuf.hdr.dest_addr.s_addr == INADDR_BROADCAST) {

		if (udp->dest_port != HTONS(SQUEEZEBOX_PORT)
				&& udp->dest_port != HTONS(UE_RADIO_PORT)) {
			INFO("Ignoring packet %s\n", udp_from_to(udp));
			return;
		}
	}
	else {
		if (pktbuf.hdr.dest_addr.s_addr != HTONL(SSDP_INADDR)
				|| udp->dest_port != HTONS(SSDP_PORT)) {
			WARN("Received unexpected packet %s\n",
			     udp_from_to(udp));
		}
	}

	send_addr.sin_addr = pktbuf.hdr.dest_addr;
	iov.iov_len = pkt_size;

	if (sendmsg(sender, &mh, 0) < 0)
		FATAL("Sending of packet %s failed: %m\n", udp_from_to(udp));

	DEBUG("Forwarded %zd byte packet %s\n", pkt_size, udp_from_to(udp));
}


/*
 * Main function - setup & event loop
 */

#define PFD_BCAST	0
#define PFD_MCAST	1

int main(int argc, char *argv[])
{
	struct pollfd pfds[2];
	int sender, ret;

	argv += parse_args(argc, argv);

	pfds[PFD_BCAST].fd = setup_bcast_listener(argv[1]);
	pfds[PFD_BCAST].events = POLLIN;

	pfds[PFD_MCAST].fd = setup_mcast_listener(argv[1]);
	pfds[PFD_MCAST].events = POLLIN;

	sender = setup_sender(argv[2]);

	NOTICE("Forwarding from %s to %s\n", argv[1], argv[2]);

	while (1) {

		pfds[PFD_BCAST].revents = 0;
		pfds[PFD_MCAST].revents = 0;

		ret = poll(pfds, 2, -1);
		if (ret < 0)
			FATAL("poll: %m\n");

		if (ret == 0)
			continue;

		if (pfds[PFD_BCAST].revents & POLLIN)
			process_packet(pfds[PFD_BCAST].fd, sender, "broadcast");
		if (pfds[PFD_MCAST].revents & POLLIN)
			process_packet(pfds[PFD_MCAST].fd, sender, "multicast");
	}

	return 0;
}
