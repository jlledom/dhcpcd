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

#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>

#include <pcap.h>

#include "logerr.h"
#include "bpf.h"

#define PCAP_CHECK(call, name) do { \
    int status = (call); \
    if (status < 0) \
        logerrx("%s: %s failed: %s", __func__, name, pcap_statustostr(status)); \
    else if (status > 0) \
        logwarnx("%s: %s warning: %s", __func__, name, pcap_statustostr(status)); \
} while(0)

#define ETH_MTU 1500

const char *bpf_name = "BPF over libpcap";

struct bpf *
bpf_open(const struct interface *ifp,
    int (*filter)(const struct bpf *, const struct in_addr *),
    __unused const struct in_addr *ia) {
    int err;
    struct bpf *bpf;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    bpf = calloc(1, sizeof(*bpf));
    if (bpf == NULL)
        return NULL;

    bpf->bpf_ifp = ifp;
    bpf->bpf_size = 0; /* We use libpcap buffer */
    bpf->bpf_len = 0;
    bpf->bpf_pos = 0;
    bpf->bpf_flags = BPF_EOF;

    handle = pcap_create(ifp->name, errbuf);
    if(handle == NULL) {
        logerrx("%s: cannot open pcap handle: %s", __func__, errbuf);
        goto eexit;
    }

    PCAP_CHECK(pcap_set_snaplen(handle, ETH_MTU), "pcap_set_snaplen");
    PCAP_CHECK(pcap_set_promisc(handle, 0), "pcap_set_promisc");
    PCAP_CHECK(pcap_set_immediate_mode(handle, 1), "pcap_set_immediate_mode");

    err = pcap_activate(handle);
    if (err != 0) {
        if (err < 0) {
            logerrx("%s: pcap_activate failed: %s", __func__, pcap_statustostr(err));
            goto eexit;
        }
        logwarnx("%s: pcap_activate warning: %s", __func__, pcap_statustostr(err));
    }

    bpf->bpf_fd = pcap_get_selectable_fd(handle);
    if(bpf->bpf_fd < 0) {
        logerrx("%s: pcap_get_selectable_fd failed", __func__);
        goto eexit;
    }

    bpf->bpf_handle = handle;

    if (filter(bpf, ia) != 0)
        goto eexit;

    return bpf;

eexit:
    free(bpf);
    return NULL;
}

ssize_t
bpf_read(struct bpf *bpf, void *data, size_t len) {
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    size_t cap_len;
    int err;

    bpf->bpf_flags |= BPF_EOF; /* We only read one packet per call */

    err = pcap_next_ex(bpf->bpf_handle, &pkt_header, &pkt_data);

    if (err < 0)
        return -1;

    /* Packet read successfully */
    cap_len = pkt_header->caplen;
    if (cap_len > len)
        cap_len = len;
    memcpy(data, pkt_data, cap_len);

    return (ssize_t)cap_len;
}

ssize_t
bpf_send(const struct bpf *bpf, uint16_t protocol,
    const void *data, size_t len)
{
    struct iovec iov[2];
    struct ether_header eh;
    char *buffer;
    size_t buflen;
    int ret;

    switch(bpf->bpf_ifp->hwtype) {
        case ARPHRD_ETHER:
            memset(&eh.ether_dhost, 0xff, sizeof(eh.ether_dhost));
            memcpy(&eh.ether_shost, bpf->bpf_ifp->hwaddr,
                sizeof(eh.ether_shost));
            eh.ether_type = htons(protocol);
            iov[0].iov_base = &eh;
            iov[0].iov_len = sizeof(eh);
            break;
        default:
            iov[0].iov_base = NULL;
            iov[0].iov_len = 0;
            break;
    }
    iov[1].iov_base = UNCONST(data);
    iov[1].iov_len = len;

    if (iov[0].iov_len > (SIZE_MAX - iov[1].iov_len)) {
        logerrx("%s: buffer length overflow", __func__);
        return -1;
    }

    buflen = iov[0].iov_len + iov[1].iov_len;
    buffer = calloc(1, buflen);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, iov[0].iov_base, iov[0].iov_len);
    memcpy(buffer + iov[0].iov_len, iov[1].iov_base, iov[1].iov_len);

    ret = pcap_inject(bpf->bpf_handle, buffer, buflen);

    free(buffer);
    return ret;
}

int
bpf_attach(const struct bpf *bpf, void *filter, unsigned int filter_len) {
    struct bpf_program pf = { .bf_insns = filter, .bf_len = filter_len };

    /* Install the filter. */
    return pcap_setfilter(bpf->bpf_handle, &pf);
}

void
bpf_close(struct bpf *bpf)
{
    pcap_close(bpf->bpf_handle);
    free(bpf);
}
