/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * libpcap interface driver for dhcpcd
 * Copyright (c) 2025 Joan Lledó <jlledom@member.fsf.org>
 * All rights reserved

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <string.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <hurd.h>
#include <hurd/paths.h>
#include <hurd/pfinet.h>
#include <device/device.h>

#include "logerr.h"
#include "if.h"
#include "dhcpcd.h"

#define ETH_HWADDR_LEN 6

/* Get the MAC address from an array of int */
#define GET_HWADDR_BYTE(x,n)  (((unsigned char*)x)[n])

/*
 * We should just use `struct ifrtreq` from net/route.h instead of defining this.
 * Regrettably, dhcpcd defines some macros inside `struct rt` that conflict with
 * `struct ifrtreq` fields, so we need to mimic `struct ifrtreq` here, but
 * renaming the fields.
 */
struct kroute {
  char ifname[IF_NAMESIZE];
  in_addr_t dest;
  in_addr_t mask;
  in_addr_t gateway;
  int flags;
  int mtu;
  int metric;
  char padding[sizeof(int) * 4];
};

int
if_getssid(__unused struct interface *ifp) {
    /* Not supported. Returning -1 means interface is not wireless */
    errno = EOPNOTSUPP;
    return -1;
}

bool
if_roaming(__unused struct interface *ifp) {
    /* Not supported */
    errno = EOPNOTSUPP;
    return false;
}

static int
if_copyrt(struct dhcpcd_ctx *ctx, struct rt *dest, struct kroute *src) {
  struct interface *ifp;

  ifp = if_find(ctx->ifaces, src->ifname);
  if (ifp == NULL) {
      logerr("%s: interface not found: %s", __func__, src->ifname);
      return -1;
  }

  memset(dest, 0, sizeof(struct rt));

  dest->rt_ifp = ifp;
  dest->rt_ss_dest.sin.sin_family = AF_INET;
  dest->rt_ss_dest.sin.sin_len = sizeof(struct sockaddr_in);
  dest->rt_ss_dest.sin.sin_addr.s_addr = src->dest;
  dest->rt_ss_netmask.sin.sin_family = AF_INET;
  dest->rt_ss_netmask.sin.sin_len = sizeof(struct sockaddr_in);
  dest->rt_ss_netmask.sin.sin_addr.s_addr = src->mask;
  dest->rt_ss_gateway.sin.sin_family = AF_INET;
  dest->rt_ss_gateway.sin.sin_len = sizeof(struct sockaddr_in);
  dest->rt_ss_gateway.sin.sin_addr.s_addr = src->gateway;
  dest->rt_flags = (unsigned int)src->flags;
  dest->rt_mtu = (unsigned int)src->mtu;
#ifdef HAVE_ROUTE_METRIC
  dest->rt_metric = (unsigned int)src->metric;
#endif

  return 0;
}

static int
if_copykrt(struct kroute *dst, const struct rt *src) {
  memset(dst, 0, sizeof(struct kroute));

  strncpy(dst->ifname, src->rt_ifp->name, IF_NAMESIZE);
  dst->dest = src->rt_ss_dest.sin.sin_addr.s_addr;;
  dst->mask = src->rt_ss_netmask.sin.sin_addr.s_addr;
  dst->gateway = src->rt_ss_gateway.sin.sin_addr.s_addr;
  dst->flags = (int)src->rt_flags;
  dst->mtu = (int)src->rt_mtu;
#ifdef HAVE_ROUTE_METRIC
  dst->metric = (int)src->rt_metric;
#endif

  /* Set flags. Required by pfinet, ignored by lwip */

  /* All dhcp routes must be marked as static */
  dst->flags |= RTF_STATIC;

  /* Flag route type */
  if (dst->mask == INADDR_NONE)
    /* All ones netmask means host route */
    dst->flags |= RTF_HOST;
  else if (dst->mask != INADDR_ANY)
    /* Subnet route */
    dst->flags &= ~RTF_HOST;
  else if (dst->gateway != INADDR_ANY)
    /* Netmask is any, and we got a gateway so default route */
    dst->flags |= RTF_GATEWAY;

  return 0;
}

/* Get all routes for existing interfaces and add them to th RB tree */
int
if_initrt(struct dhcpcd_ctx *ctx, rb_tree_t *routes, int af) {
  mach_port_t pfinet;
  char socket_inet[32];
  char *raw_data;
  struct kroute *kroutes;
  unsigned int i, len = 0, kroutes_count;
  struct rt rt, *rtn = NULL;
  error_t err;

  snprintf(socket_inet, sizeof(socket_inet), _SERVERS_SOCKET "/%d", af);
  pfinet = file_name_lookup (socket_inet, O_RDONLY, 0);
  if (pfinet == MACH_PORT_NULL) {
      logerr("%s: cannot open file: %s", __func__, socket_inet);
      return -1;
  }

  err = pfinet_getroutes (pfinet, (vm_size_t)-1, &raw_data, &len);
  if (err) {
      errno = err;
      logerr("%s: cannot get routes from stack", __func__);
      goto errout;
  }

  kroutes = (struct kroute *)raw_data;
  kroutes_count = len / sizeof(struct kroute);

  for (i = 0; i < kroutes_count; i++) {
    if (if_copyrt(ctx, &rt, &kroutes[i]) != 0)
      goto errout;

    if ((rtn = rt_new(rt.rt_ifp)) == NULL) {
      goto errout;
    }

    memcpy(rtn, &rt, sizeof(*rtn));

    if (rb_tree_insert_node(routes, rtn) != rtn)
      rt_free(rtn);
  }

  mach_port_deallocate (mach_task_self (), pfinet);
  vm_deallocate (mach_task_self(), (vm_address_t)raw_data, len);

  return 0;

errout:
  mach_port_deallocate (mach_task_self (), pfinet);

  if (raw_data)
    vm_deallocate (mach_task_self(), (vm_address_t)raw_data, len);

  return -1;
}

int
if_vimaster(__unused struct dhcpcd_ctx *ctx, __unused const char *ifname) {
    /* Used mostly for wlan. Not supported */
    errno = EOPNOTSUPP;
    return -1;
}

#ifdef INET
int
if_route(unsigned char cmd, const struct rt *rt) {
  struct dhcpcd_ctx *ctx;
  struct kroute krt;

  if (cmd == RTM_CHANGE) {
    /*
     * Asked to change route, the hurd doesn't provide a way to do this,
     * available ioctls only allow adding and deleting.
     * ESRCH is the expected error in this scenario.
     */
    errno = ESRCH;
    return -1;
  }

  ctx = rt->rt_ifp->ctx;

  if_copykrt(&krt, rt);
  return if_ioctl(ctx, cmd == RTM_DELETE ? SIOCDELRT : SIOCADDRT, &krt, sizeof(krt));
}

static int
if_ioctl_addr(struct dhcpcd_ctx *ctx, const char *ifname,
    const struct in_addr *addr, ioctl_request_t cmd) {
    struct ifreq ifr;
    struct sockaddr_in *sin;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr = *addr;
    sin->sin_len = sizeof(struct sockaddr_in);

    return if_ioctl(ctx, cmd, &ifr, sizeof(ifr));
}

int
if_address(unsigned char cmd, const struct ipv4_addr *ia) {
    int err;
    struct in_addr addr;

    if (cmd == RTM_DELADDR) {
      addr.s_addr = ia->addr.s_addr;
      err = if_ioctl_addr(ia->iface->ctx, ia->iface->name, &addr, SIOCDIFADDR);
      if (err) {
        logerr("%s: cannot delete address", __func__);
        return -1;
      }

      return 0;
    }

    addr.s_addr = ia->addr.s_addr;
    err = if_ioctl_addr(ia->iface->ctx, ia->iface->name, &addr, SIOCSIFADDR);
    if (err) {
      logerr("%s: cannot set address", __func__);
      return -1;
    }

    addr.s_addr = ia->mask.s_addr;
    err = if_ioctl_addr(ia->iface->ctx, ia->iface->name, &addr, SIOCSIFNETMASK);
    if (err) {
      logerr("%s: cannot set network mask", __func__);
      return -1;
    }

    addr.s_addr = ia->brd.s_addr;
    err = if_ioctl_addr(ia->iface->ctx, ia->iface->name, &addr, SIOCSIFBRDADDR);
    if (err && errno != ENOTTY) {
      /* We have to accept ENOTTY as a success state here because lwip doesn't
       * accept setting a broadcast address, it's a computed value.
       * About pfinet, we expect to get a ENOTTY only when it doesn't get an
       * authorized user. Not possible here because in that case previous calls
       * would fail and the code wouldn't reach here.
       */
      logerr("%s: cannot set broadcast address", __func__);
      return -1;
    }

  return 0;
}

int
if_addrflags(__unused const struct interface *ifp, __unused const struct in_addr *addr,
    __unused const char *alias) {
    /* Not supported. Set flags to 0 */
    return 0;
}
#endif

#ifdef INET6
int
if_address6(__unused unsigned char cmd, __unused const struct ipv6_addr *ia) {
    /* TODO  */
    return -1;
}

int
if_getlifetime6(__unused struct ipv6_addr *addr) {
    /* TODO  */
    return -1;
}

int
if_addrflags6(__unused const struct interface *ifp, __unused const struct in6_addr *addr,
    __unused const char *alias) {
    /* TODO  */
    return -1;
}

void
if_setup_inet6(__unused const struct interface *ifp) {
    /* TODO */
}

int
if_applyra(__unused const struct ra *rap) {
    /* TODO  */
    return -1;
}
#endif

#ifdef PRIVSEP
ssize_t
ps_root_os(__unused struct dhcpcd_ctx *ctx, __unused struct ps_msghdr *psm, __unused struct msghdr *msg,
    __unused void **rdata, __unused size_t *rlen, __unused bool *free_data) {
    /* TODO  */
    return -1;
}
#endif

int
os_init(void) {
    /* Not needed for now */
    return 0;
}

/*
 * Initialize the given interface.
 * Try to get its MAC address and index
 */
int
if_init(struct interface *ifp) {
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifp->name, IFNAMSIZ);

    /* Don't try to get HW address for loopback interfaces */
    if ((ifp->flags & IFF_LOOPBACK) == 0) {
      if (ioctl(ifp->ctx->pf_inet_fd, SIOCGIFHWADDR, &ifr) == -1) {
        logerr("%s: SIOCGIFHWADDR", ifp->name);
        return -1;
      }
      memcpy(ifp->hwaddr, ifr.ifr_hwaddr.sa_data, ETH_HWADDR_LEN);
      ifp->hwtype = ifr.ifr_hwaddr.sa_family;
      ifp->hwlen = ifr.ifr_hwaddr.sa_len;
    }

    if (ioctl(ifp->ctx->pf_inet_fd, SIOCGIFINDEX, &ifr) == -1) {
      logerr("%s: SIOCGIFINDEX", ifp->name);
      return -1;
    }
    ifp->index = (unsigned int)ifr.ifr_ifindex;

    return 0;
}

int
if_opensockets_os(__unused struct dhcpcd_ctx *ctx) {
    ctx->link_fd = -1;

    return 0;
}

void
if_closesockets_os(__unused struct dhcpcd_ctx *ctx) {
    /* Nothing to do, as link_fd is not initialized */
}

int
if_conf(__unused struct interface *ifp) {
    /* Not needed for now */
    return 0;
}

int
if_handlelink(__unused struct dhcpcd_ctx *ctx) {
    /* No needed if link_fd is not initialized */
    return 0;
}

int
if_setmac(__unused struct interface *ifp, __unused void *mac, __unused uint8_t maclen) {
    errno = EOPNOTSUPP;
    return -1;
}

unsigned short
if_vlanid(__unused const struct interface *ifp) {
    /* We don't support vlans for now */
    return 0;
}

int
if_carrier(struct interface *ifp, __unused const void *ifadata) {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strlcpy(ifr.ifr_name, ifp->name, IFNAMSIZ);

  if (ioctl(ifp->ctx->pf_inet_fd, SIOCGIFFLAGS, &ifr) == -1) {
    logerr("%s: SIOCGIFFLAGS", ifp->name);
    return LINK_UNKNOWN;
  }

  if (ifr.ifr_flags & IFF_RUNNING)
    return LINK_UP;

  return LINK_DOWN;
}

bool
if_ignore(__unused struct dhcpcd_ctx *ctx, __unused const char *ifname) {
    /*
     * Return `true` for interfaces we want dhcpcd to ignore.
     *
     * Other OSs use this to ignore taps, bridges, and other kinds of
     * virtual interfaces.
     *
     * We don't use this for now.
     */
    return false;
}

int
if_machinearch(__unused char *str, __unused size_t len) {
    /*
     * dhcpcd already has uname info.
     * We don't need to add extra architecture info for now.
     */
    return 0;
}
