/**
 * Copyright (C) 2012-2013 Steven Barth <steven@midlink.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <resolv.h>
#include <getopt.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <netpacket/packet.h>
#include <linux/rtnetlink.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include <libubox/uloop.h>
#include "odhcpd.h"



static int ioctl_sock;
static int rtnl_socket = -1;
static int rtnl_seq = 0;
static int urandom_fd = -1;


static void sighandler(_unused int signal)
{
	uloop_end();
}


int main()
{
	openlog("odhcpd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	char *env_log_level = getenv("ODHCPD_LOG_LEVEL");
	int log_level = LOG_WARNING;
	if (env_log_level) {
		char *end;
		errno = 0;
		long temp = strtol(env_log_level, &end, 0);
		if (end == env_log_level || *end != '\0'
			|| ((temp == LONG_MIN || temp == LONG_MAX) && errno == ERANGE)
			|| (log_level > LOG_DEBUG) || log_level < LOG_EMERG) {
			syslog(LOG_ERR, "ODHCPD_LOG_LEVEL envvar was invalid");
		} else {
			log_level = temp;
		}
	}
	setlogmask(LOG_UPTO(log_level));
	uloop_init();

	if (getuid() != 0) {
		syslog(LOG_ERR, "Must be run as root!");
		return 2;
	}

	ioctl_sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

	if ((rtnl_socket = odhcpd_open_rtnl()) < 0) {
		syslog(LOG_ERR, "Unable to open socket: %s", strerror(errno));
		return 2;
	}

	if ((urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC)) < 0)
		return 4;

	signal(SIGUSR1, SIG_IGN);
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	if (init_router())
		return 4;

	if (init_dhcpv6())
		return 4;

	if (init_ndp())
		return 4;

	if (init_dhcpv4())
		return 4;

	odhcpd_run();
	return 0;
}

int odhcpd_open_rtnl(void)
{
	int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);

	// Connect to the kernel netlink interface
	struct sockaddr_nl nl = {.nl_family = AF_NETLINK};
	if (connect(sock, (struct sockaddr*)&nl, sizeof(nl))) {
		syslog(LOG_ERR, "Failed to connect to kernel rtnetlink: %s",
				strerror(errno));
		return -1;
	}

	return sock;
}


// Read IPv6 MTU for interface
int odhcpd_get_interface_config(const char *ifname, const char *what)
{
	char buf[64];
	const char *sysctl_pattern = "/proc/sys/net/ipv6/conf/%s/%s";
	snprintf(buf, sizeof(buf), sysctl_pattern, ifname, what);

	int fd = open(buf, O_RDONLY);
	ssize_t len = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (len < 0)
		return -1;

	buf[len] = 0;
	return atoi(buf);
}


// Read IPv6 MAC for interface
int odhcpd_get_mac(const struct interface *iface, uint8_t mac[6])
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface->ifname, sizeof(ifr.ifr_name));
	if (ioctl(ioctl_sock, SIOCGIFHWADDR, &ifr) < 0)
		return -1;
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}


// Forwards a packet on a specific interface
ssize_t odhcpd_send(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct interface *iface)
{
	// Construct headers
	uint8_t cmsg_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
	struct msghdr msg = {
		.msg_name = (void *) dest,
		.msg_namelen = sizeof(*dest),
		.msg_iov = iov,
		.msg_iovlen = iov_len,
		.msg_control = cmsg_buf,
		.msg_controllen = sizeof(cmsg_buf),
		.msg_flags = 0
	};

	// Set control data (define destination interface)
	struct cmsghdr *chdr = CMSG_FIRSTHDR(&msg);
	chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_PKTINFO;
	chdr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	struct in6_pktinfo *pktinfo = (struct in6_pktinfo*)CMSG_DATA(chdr);
	pktinfo->ipi6_ifindex = iface->ifindex;

	// Also set scope ID if link-local
	if (IN6_IS_ADDR_LINKLOCAL(&dest->sin6_addr)
			|| IN6_IS_ADDR_MC_LINKLOCAL(&dest->sin6_addr))
		dest->sin6_scope_id = iface->ifindex;

	char ipbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &dest->sin6_addr, ipbuf, sizeof(ipbuf));

	ssize_t sent = sendmsg(socket, &msg, MSG_DONTWAIT);
	if (sent < 0)
		syslog(LOG_NOTICE, "Failed to send to %s%%%s (%s)",
				ipbuf, iface->ifname, strerror(errno));
	else
		syslog(LOG_DEBUG, "Sent %li bytes to %s%%%s",
				(long)sent, ipbuf, iface->ifname);
	return sent;
}


// Detect an IPV6-address currently assigned to the given interface
ssize_t odhcpd_get_interface_addresses(int ifindex,
		struct odhcpd_ipaddr *addrs, size_t cnt)
{
	struct {
		struct nlmsghdr nhm;
		struct ifaddrmsg ifa;
	} req = {{sizeof(req), RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP,
			++rtnl_seq, 0}, {AF_INET6, 0, 0, 0, ifindex}};
	if (send(rtnl_socket, &req, sizeof(req), 0) < (ssize_t)sizeof(req))
		return 0;

	uint8_t buf[8192];
	ssize_t len = 0, ret = 0;

	for (struct nlmsghdr *nhm = NULL; ; nhm = NLMSG_NEXT(nhm, len)) {
		while (len < 0 || !NLMSG_OK(nhm, (size_t)len)) {
			len = recv(rtnl_socket, buf, sizeof(buf), 0);
			nhm = (struct nlmsghdr*)buf;
			if (len < 0 || !NLMSG_OK(nhm, (size_t)len)) {
				if (errno == EINTR)
					continue;
				else
					return ret;
			}
		}

		if (nhm->nlmsg_type != RTM_NEWADDR)
			break;

		// Skip address but keep clearing socket buffer
		if (ret >= (ssize_t)cnt)
			continue;

		struct ifaddrmsg *ifa = NLMSG_DATA(nhm);
		if (ifa->ifa_scope != RT_SCOPE_UNIVERSE ||
				(ifindex && ifa->ifa_index != (unsigned)ifindex))
			continue;

		struct rtattr *rta = (struct rtattr*)&ifa[1];
		size_t alen = NLMSG_PAYLOAD(nhm, sizeof(*ifa));
		memset(&addrs[ret], 0, sizeof(addrs[ret]));
		addrs[ret].prefix = ifa->ifa_prefixlen;

		while (RTA_OK(rta, alen)) {
			if (rta->rta_type == IFA_ADDRESS) {
				memcpy(&addrs[ret].addr, RTA_DATA(rta),
						sizeof(struct in6_addr));
			} else if (rta->rta_type == IFA_CACHEINFO) {
				struct ifa_cacheinfo *ifc = RTA_DATA(rta);
				addrs[ret].preferred = ifc->ifa_prefered;
				addrs[ret].valid = ifc->ifa_valid;
			}

			rta = RTA_NEXT(rta, alen);
		}

		if (ifa->ifa_flags & IFA_F_DEPRECATED)
			addrs[ret].preferred = 0;

		++ret;
	}

	return ret;
}

int odhcpd_get_linklocal_interface_address(int ifindex, struct in6_addr *lladdr)
{
		int status = -1;
		struct sockaddr_in6 addr = {AF_INET6, 0, 0, ALL_IPV6_ROUTERS, ifindex};
		socklen_t alen = sizeof(addr);
		int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

		if (!connect(sock, (struct sockaddr*)&addr, sizeof(addr)) &&
				!getsockname(sock, (struct sockaddr*)&addr, &alen)) {
			*lladdr = addr.sin6_addr;
			status = 0;
		}

		close(sock);
		return status;
}

void odhcpd_setup_route(const struct in6_addr *addr, int prefixlen,
		const struct interface *iface, const struct in6_addr *gw,
		int metric, bool add)
{
	struct req {
		struct nlmsghdr nh;
		struct rtmsg rtm;
		struct rtattr rta_dst;
		struct in6_addr dst_addr;
		struct rtattr rta_oif;
		uint32_t ifindex;
		struct rtattr rta_table;
		uint32_t table;
		struct rtattr rta_prio;
		uint32_t prio;
		struct rtattr rta_gw;
		struct in6_addr gw;
	} req = {
		{sizeof(req), 0, NLM_F_REQUEST, ++rtnl_seq, 0},
		{AF_INET6, prefixlen, 0, 0, 0, 0, 0, 0, 0},
		{sizeof(struct rtattr) + sizeof(struct in6_addr), RTA_DST},
		*addr,
		{sizeof(struct rtattr) + sizeof(uint32_t), RTA_OIF},
		iface->ifindex,
		{sizeof(struct rtattr) + sizeof(uint32_t), RTA_TABLE},
		RT_TABLE_MAIN,
		{sizeof(struct rtattr) + sizeof(uint32_t), RTA_PRIORITY},
		metric,
		{sizeof(struct rtattr) + sizeof(struct in6_addr), RTA_GATEWAY},
		IN6ADDR_ANY_INIT,
	};

	if (gw)
		req.gw = *gw;

	if (add) {
		req.nh.nlmsg_type = RTM_NEWROUTE;
		req.nh.nlmsg_flags |= (NLM_F_CREATE | NLM_F_REPLACE);
		req.rtm.rtm_protocol = RTPROT_STATIC;
		req.rtm.rtm_scope = (gw) ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
		req.rtm.rtm_type = RTN_UNICAST;
	} else {
		req.nh.nlmsg_type = RTM_DELROUTE;
		req.rtm.rtm_scope = RT_SCOPE_NOWHERE;
	}

	req.nh.nlmsg_len = (gw) ? sizeof(req) : offsetof(struct req, rta_gw);
	send(rtnl_socket, &req, req.nh.nlmsg_len, MSG_DONTWAIT);
}

struct interface* odhcpd_get_interface_by_index(int ifindex)
{
	struct interface *iface;
	list_for_each_entry(iface, &interfaces, head)
		if (iface->ifindex == ifindex)
			return iface;

	return NULL;
}


struct interface* odhcpd_get_interface_by_name(const char *name)
{
	struct interface *iface;
	list_for_each_entry(iface, &interfaces, head)
		if (!strcmp(iface->ifname, name))
			return iface;

	return NULL;
}


struct interface* odhcpd_get_master_interface(void)
{
	struct interface *iface;
	list_for_each_entry(iface, &interfaces, head)
		if (iface->master)
			return iface;

	return NULL;
}


// Convenience function to receive and do basic validation of packets
static void odhcpd_receive_packets(struct uloop_fd *u, _unused unsigned int events)
{
	struct odhcpd_event *e = container_of(u, struct odhcpd_event, uloop);

	uint8_t data_buf[RELAYD_BUFFER_SIZE], cmsg_buf[128];
	union {
		struct sockaddr_in6 in6;
		struct sockaddr_in in;
		struct sockaddr_ll ll;
		struct sockaddr_nl nl;
	} addr;

	if (u->error) {
		int ret = -1;
		socklen_t ret_len = sizeof(ret);
		getsockopt(u->fd, SOL_SOCKET, SO_ERROR, &ret, &ret_len);
		u->error = false;
		if (e->handle_error)
			e->handle_error(ret);
	}

	while (true) {
		struct iovec iov = {data_buf, sizeof(data_buf)};
		struct msghdr msg = {
			.msg_name = (void *) &addr,
			.msg_namelen = sizeof(addr),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cmsg_buf,
			.msg_controllen = sizeof(cmsg_buf),
			.msg_flags = 0
		};

		ssize_t len = recvmsg(u->fd, &msg, MSG_DONTWAIT);
		if (len < 0) {
			if (errno == EAGAIN)
				break;
			else
				continue;
		}


		// Extract destination interface
		int destiface = 0;
		int *hlim = NULL;
		void *dest = NULL;
		struct in6_pktinfo *pktinfo;
		struct in_pktinfo *pkt4info;
		for (struct cmsghdr *ch = CMSG_FIRSTHDR(&msg); ch != NULL; ch = CMSG_NXTHDR(&msg, ch)) {
			if (ch->cmsg_level == IPPROTO_IPV6 &&
					ch->cmsg_type == IPV6_PKTINFO) {
				pktinfo = (struct in6_pktinfo*)CMSG_DATA(ch);
				destiface = pktinfo->ipi6_ifindex;
				dest = &pktinfo->ipi6_addr;
			} else if (ch->cmsg_level == IPPROTO_IP &&
					ch->cmsg_type == IP_PKTINFO) {
				pkt4info = (struct in_pktinfo*)CMSG_DATA(ch);
				destiface = pkt4info->ipi_ifindex;
				dest = &pkt4info->ipi_addr;
			} else if (ch->cmsg_level == IPPROTO_IPV6 &&
					ch->cmsg_type == IPV6_HOPLIMIT) {
				hlim = (int*)CMSG_DATA(ch);
			}
		}

		// Check hoplimit if received
		if (hlim && *hlim != 255)
			continue;

		// Detect interface for packet sockets
		if (addr.ll.sll_family == AF_PACKET)
			destiface = addr.ll.sll_ifindex;

		struct interface *iface =
				odhcpd_get_interface_by_index(destiface);

		if (!iface && addr.nl.nl_family != AF_NETLINK)
			continue;

		char ipbuf[INET6_ADDRSTRLEN] = "kernel";
		if (addr.ll.sll_family == AF_PACKET &&
				len >= (ssize_t)sizeof(struct ip6_hdr))
			inet_ntop(AF_INET6, &data_buf[8], ipbuf, sizeof(ipbuf));
		else if (addr.in6.sin6_family == AF_INET6)
			inet_ntop(AF_INET6, &addr.in6.sin6_addr, ipbuf, sizeof(ipbuf));
		else if (addr.in.sin_family == AF_INET)
			inet_ntop(AF_INET, &addr.in.sin_addr, ipbuf, sizeof(ipbuf));

		syslog(LOG_DEBUG, "--");
		syslog(LOG_DEBUG, "Received %li Bytes from %s%%%s", (long)len,
				ipbuf, (iface) ? iface->ifname : "netlink");

		e->handle_dgram(&addr, data_buf, len, iface, dest);
	}
}

// Register events for the multiplexer
int odhcpd_register(struct odhcpd_event *event)
{
	event->uloop.cb = odhcpd_receive_packets;
	return uloop_fd_add(&event->uloop, ULOOP_READ |
			((event->handle_error) ? ULOOP_ERROR_CB : 0));
}

void odhcpd_process(struct odhcpd_event *event)
{
	odhcpd_receive_packets(&event->uloop, 0);
}

int odhcpd_urandom(void *data, size_t len)
{
	return read(urandom_fd, data, len);
}


time_t odhcpd_time(void)
{
	struct timespec ts;
	syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}


static const char hexdigits[] = "0123456789abcdef";
static const int8_t hexvals[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -1, -1, -2, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

ssize_t odhcpd_unhexlify(uint8_t *dst, size_t len, const char *src)
{
	size_t c;
	for (c = 0; c < len && src[0] && src[1]; ++c) {
		int8_t x = (int8_t)*src++;
		int8_t y = (int8_t)*src++;
		if (x < 0 || (x = hexvals[x]) < 0
				|| y < 0 || (y = hexvals[y]) < 0)
			return -1;
		dst[c] = x << 4 | y;
		while (((int8_t)*src) < 0 ||
				(*src && hexvals[(uint8_t)*src] < 0))
			src++;
	}

	return c;
}


void odhcpd_hexlify(char *dst, const uint8_t *src, size_t len)
{
	for (size_t i = 0; i < len; ++i) {
		*dst++ = hexdigits[src[i] >> 4];
		*dst++ = hexdigits[src[i] & 0x0f];
	}
	*dst = 0;
}


int odhcpd_bmemcmp(const void *av, const void *bv, size_t bits)
{
	const uint8_t *a = av, *b = bv;
	size_t bytes = bits / 8;
	bits %= 8;

	int res = memcmp(a, b, bytes);
	if (res == 0 && bits > 0)
		res = (a[bytes] >> (8 - bits)) - (b[bytes] >> (8 - bits));

	return res;
}


void odhcpd_bmemcpy(void *av, const void *bv, size_t bits)
{
	uint8_t *a = av;
	const uint8_t *b = bv;

	size_t bytes = bits / 8;
	bits %= 8;
	memcpy(a, b, bytes);

	if (bits > 0) {
		uint8_t mask = (1 << (8 - bits)) - 1;
		a[bytes] = (a[bytes] & mask) | ((~mask) & b[bytes]);
	}
}
