// Copyright (C) 2012 - Will Glozer.  All rights reserved.

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "units.h"
#include "aprintf.h"

typedef struct {
    int scale;
    char *base;
    char *units[];
} units;

units time_units_us = {
    .scale = 1000,
    .base  = "us",
    .units = { "ms", "s", NULL }
};

units time_units_s = {
    .scale = 60,
    .base  = "s",
    .units = { "m", "h", NULL }
};

units binary_units = {
    .scale = 1024,
    .base  = "",
    .units = { "K", "M", "G", "T", "P", NULL }
};

units metric_units = {
    .scale = 1000,
    .base  = "",
    .units = { "k", "M", "G", "T", "P", NULL }
};

static char *format_units(long double n, units *m, int p) {
    long double amt = n, scale;
    char *unit = m->base;
    char *msg = NULL;

    scale = m->scale * 0.85;

    for (int i = 0; m->units[i+1] && amt >= scale; i++) {
        amt /= m->scale;
        unit = m->units[i];
    }

    aprintf(&msg, "%.*Lf%s", p, amt, unit);

    return msg;
}

static int scan_units(char *s, uint64_t *n, units *m) {
    uint64_t base, scale = 1;
    char unit[3] = { 0, 0, 0 };
    int i, c;

    if ((c = sscanf(s, "%"SCNu64"%2s", &base, unit)) < 1) return -1;

    if (c == 2 && strncasecmp(unit, m->base, 3)) {
        for (i = 0; m->units[i] != NULL; i++) {
            scale *= m->scale;
            if (!strncasecmp(unit, m->units[i], 3)) break;
        }
        if (m->units[i] == NULL) return -1;
    }

    *n = base * scale;
    return 0;
}

char *format_binary(long double n) {
    return format_units(n, &binary_units, 2);
}

char *format_metric(long double n) {
    return format_units(n, &metric_units, 2);
}

char *format_time_us(long double n) {
    units *units = &time_units_us;
    if (n >= 1000000.0) {
        n /= 1000000.0;
        units = &time_units_s;
    }
    return format_units(n, units, 2);
}

char *format_time_s(long double n) {
    return format_units(n, &time_units_s, 0);
}

int scan_metric(char *s, uint64_t *n) {
    return scan_units(s, n, &metric_units);
}

int scan_time(char *s, uint64_t *n) {
    return scan_units(s, n, &time_units_s);
}

int scan_cidr_range(char *s, cidr_range *cr) {
    char addr_buf[46];
    unsigned int mask_len;
    int scan_res, gai_res;
    struct addrinfo hints, *result;
    unsigned __int128 base, mask, full_mask, temp;

    mask_len = 0;
    scan_res = sscanf(s, "%45[^/]/%u", addr_buf, &mask_len);

    if (scan_res == 0) {
        fprintf(stderr, "IP address could not be read!\n");
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    base = 0;

    gai_res = getaddrinfo(addr_buf, NULL, &hints, &result);
    if (gai_res != 0) {
        fprintf(stderr, "Can't parse IP address. getaddrinfo: %s\n", gai_strerror(gai_res));
        return -1;
    }

    if (result->ai_family == AF_INET) {
        if (mask_len == 0 && scan_res == 1) {
            mask_len = 32;
        } else if (mask_len > 32) {
            fprintf(stderr, "Netmask must be between 0 and 32!");
            return -1;
        }
        full_mask = 0xFFFFFFFF;
        mask = (full_mask << (32 - mask_len)) & full_mask;
        base = ntohl(((struct sockaddr_in*)result->ai_addr)->sin_addr.s_addr);
    } else if (result->ai_family == AF_INET6) {
        if (mask_len == 0 && scan_res == 1) {
            mask_len = 128;
        } else if (mask_len > 128) {
            fprintf(stderr, "Netmask must be between 0 and 128!");
            return -1;
        }
        full_mask = -1;
        mask = (full_mask << (128 - mask_len)) & full_mask;
            //base = *(unsigned __int128*)((struct sockaddr_in6*)result->ai_addr)->sin6_addr.s6_addr;

        for (int i=0; i<4; i++) {
            int shift = (3-i)*32;
            temp = ntohl(((struct sockaddr_in6*)result->ai_addr)->sin6_addr.s6_addr32[i]);
            temp <<= shift;
            printf("temp %08lx, i %d, shift %d\n", (long unsigned int) temp, i, shift);
            base |= temp;
        }


    } else {
        fprintf(stderr, "Unsupported address family!");
        return -1;
    }

    

    uint64_t low;
    uint64_t high;

    high = (uint64_t) base;
    low = (uint64_t) (base >> 64);
    printf("ad 0x%016lx%016lx\n", low, high);

    high = (uint64_t) full_mask;
    low = (uint64_t) (full_mask >> 64);
    printf("fm 0x%016lx%016lx\n", low, high);
    high = (uint64_t) mask;
    low = (uint64_t) (mask >> 64);
    printf("ma 0x%016lx%016lx\n", low, high);

    cr->first_ip = base & mask;
    cr->last_ip = cr->first_ip | ~mask;

    if (cr->first_ip != base) {
        fprintf(stderr, "IP address has non-network bits set!\n");
        return -1;
    }

    cr->count = cr->last_ip - cr->first_ip;
    cr->ip = cr->first_ip;

    freeaddrinfo(result);

    return 0;
}
