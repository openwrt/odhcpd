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
#include <linux/netlink.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include <netlink/msg.h>
#include <netlink/socket.h>
#include <netlink/attr.h>
#include <libubox/uloop.h>
#include "odhcpd.h"



static int ioctl_sock;
static struct nl_sock *rtnl_socket = NULL;
static int urandom_fd = -1;


static void sighandler(_unused int signal)
{
	uloop_end();
}

static void print_usage(const char *app)
{
	printf(
	"== %s Usage ==\n\n"
	"  -h, --help   Print this help\n"
	"  -l level     Specify log level 0..7 (default %d)\n",
		app, LOG_WARNING
	);
}

int main(int argc, char **argv)
{
	openlog("odhcpd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	int opt;
	int log_level = LOG_INFO;
	while ((opt = getopt(argc, argv, "hl:")) != -1) {
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			return 0;
		case 'l':
			log_level = atoi(optarg);
			fprintf(stderr, "Log level set to %d\n", log_level);
			break;
		}
	}
	setlogmask(LOG_UPTO(log_level));
	uloop_init();

	if (getuid() != 0) {
		syslog(LOG_ERR, "Must be run as root!");
		return 2;
	}

	ioctl_sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

	if (!(rtnl_socket = odhcpd_create_nl_socket(NETLINK_ROUTE))) {
		syslog(LOG_ERR, "Unable to open nl socket: %s", strerror(errno));
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

struct nl_sock *odhcpd_create_nl_socket(int protocol)
{
	struct nl_sock *nl_sock;

	nl_sock = nl_socket_alloc();
	if (!nl_sock)
		goto err;

	if (nl_connect(nl_sock, protocol) < 0)
		goto err;

	return nl_sock;

err:
	if (nl_sock)
		nl_socket_free(nl_sock);

	return NULL;
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

struct addr_info {
	int ifindex;
	struct odhcpd_ipaddr *addrs;
	size_t addrs_sz;
	int pending;
	ssize_t ret;
};

static int cb_valid_handler(struct nl_msg *msg, void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct ifaddrmsg *ifa;
	struct nlattr *nla[__IFA_MAX];

	if (hdr->nlmsg_type != RTM_NEWADDR || ctxt->ret >= (ssize_t)ctxt->addrs_sz)
		return NL_SKIP;

	ifa = NLMSG_DATA(hdr);
	if (ifa->ifa_scope != RT_SCOPE_UNIVERSE ||
			(ctxt->ifindex && ifa->ifa_index != (unsigned)ctxt->ifindex))
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ifa), nla, __IFA_MAX - 1, NULL);
	if (!nla[IFA_ADDRESS])
		return NL_SKIP;

	memset(&ctxt->addrs[ctxt->ret], 0, sizeof(ctxt->addrs[ctxt->ret]));
	ctxt->addrs[ctxt->ret].prefix = ifa->ifa_prefixlen;

	nla_memcpy(&ctxt->addrs[ctxt->ret].addr, nla[IFA_ADDRESS],
			sizeof(ctxt->addrs[ctxt->ret].addr));

	if (nla[IFA_CACHEINFO]) {
		struct ifa_cacheinfo *ifc = nla_data(nla[IFA_CACHEINFO]);

		ctxt->addrs[ctxt->ret].preferred = ifc->ifa_prefered;
		ctxt->addrs[ctxt->ret].valid = ifc->ifa_valid;
	}

	if (ifa->ifa_flags & IFA_F_DEPRECATED)
		ctxt->addrs[ctxt->ret].preferred = 0;

	ctxt->ret++;

	return NL_OK;
}

static int cb_finish_handler(_unused struct nl_msg *msg, void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;

	ctxt->pending = 0;

	return NL_STOP;
}

static int cb_error_handler(_unused struct sockaddr_nl *nla, struct nlmsgerr *err,
		void *arg)
{
	struct addr_info *ctxt = (struct addr_info *)arg;

	ctxt->pending = 0;
	ctxt->ret = err->error;

	return NL_STOP;
}

// Detect an IPV6-address currently assigned to the given interface
ssize_t odhcpd_get_interface_addresses(int ifindex,
		struct odhcpd_ipaddr *addrs, size_t cnt)
{
	struct nl_msg *msg;
	struct ifaddrmsg ifa = {
		.ifa_family = AF_INET6,
		.ifa_prefixlen = 0,
		.ifa_flags = 0,
		.ifa_scope = 0,
		.ifa_index = ifindex, };
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	struct addr_info ctxt = {
		.ifindex = ifindex,
		.addrs = addrs,
		.addrs_sz = cnt,
		.ret = 0,
		.pending = 1,
	};

	if (!cb) {
		ctxt.ret = -1;
		goto out;
	}

	msg = nlmsg_alloc_simple(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);

	if (!msg) {
		ctxt.ret = - 1;
		goto out;
	}

	nlmsg_append(msg, &ifa, sizeof(ifa), 0);

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_valid_handler, &ctxt);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, cb_finish_handler, &ctxt);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_error_handler, &ctxt);

	nl_send_auto_complete(rtnl_socket, msg);
	while (ctxt.pending > 0)
		nl_recvmsgs(rtnl_socket, cb);

	nlmsg_free(msg);
out:
	nl_cb_put(cb);

	return ctxt.ret;
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

int odhcpd_setup_route(const struct in6_addr *addr, const int prefixlen,
		const struct interface *iface, const struct in6_addr *gw,
		const uint32_t metric, const bool add)
{
	struct nl_msg *msg;
	struct rtmsg rtm = {
		.rtm_family = AF_INET6,
		.rtm_dst_len = prefixlen,
		.rtm_src_len = 0,
		.rtm_table = RT_TABLE_MAIN,
		.rtm_protocol = (add ? RTPROT_STATIC : RTPROT_UNSPEC),
		.rtm_scope = (add ? (gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK) : RT_SCOPE_NOWHERE),
		.rtm_type = (add ? RTN_UNICAST : RTN_UNSPEC),
	};
	int ret = 0;

	msg = nlmsg_alloc_simple(add ? RTM_NEWROUTE : RTM_DELROUTE,
					add ? NLM_F_CREATE | NLM_F_REPLACE : 0);
	if (!msg)
		return -1;

	nlmsg_append(msg, &rtm, sizeof(rtm), 0);

	nla_put(msg, RTA_DST, sizeof(*addr), addr);
	nla_put_u32(msg, RTA_OIF, iface->ifindex);
	nla_put_u32(msg, RTA_PRIORITY, metric);

	if (gw)
		nla_put(msg, RTA_GATEWAY, sizeof(*gw), gw);

	ret = nl_send_auto_complete(rtnl_socket, msg);
	nlmsg_free(msg);

	if (ret < 0)
		return ret;

	return nl_wait_for_ack(rtnl_socket);
}

int odhcpd_setup_proxy_neigh(const struct in6_addr *addr,
		const struct interface *iface, const bool add)
{
	struct nl_msg *msg;
	struct ndmsg ndm = {
		.ndm_family = AF_INET6,
		.ndm_flags = NTF_PROXY,
		.ndm_ifindex = iface->ifindex,
	};
	int ret = 0, flags = NLM_F_REQUEST;

	if (add)
		flags |= NLM_F_REPLACE | NLM_F_CREATE;

	msg = nlmsg_alloc_simple(add ? RTM_NEWNEIGH : RTM_DELNEIGH, flags);
	if (!msg)
		return -1;

	nlmsg_append(msg, &ndm, sizeof(ndm), 0);

	nla_put(msg, NDA_DST, sizeof(*addr), addr);

	ret = nl_send_auto_complete(rtnl_socket, msg);
	nlmsg_free(msg);

	if (ret < 0)
		return ret;

	return nl_wait_for_ack(rtnl_socket);
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
			e->handle_error(e, ret);
	}

	if (e->recv_msgs) {
		e->recv_msgs(e);
		return;
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

int odhcpd_deregister(struct odhcpd_event *event)
{
	event->uloop.cb = NULL;
	return uloop_fd_delete(&event->uloop);
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
