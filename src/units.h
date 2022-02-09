#ifndef UNITS_H
#define UNITS_H

typedef struct {

    unsigned __int128 first_ip;
    unsigned __int128 last_ip;
    unsigned __int128 count;
    unsigned __int128 ip; /* used to round-robin multiple IPs in connect_socket() */
} cidr_range;

char *format_binary(long double);
char *format_metric(long double);
char *format_time_us(long double);
char *format_time_s(long double);

int scan_metric(char *, uint64_t *);
int scan_time(char *, uint64_t *);
int scan_cidr_range(char *, cidr_range *);

#endif /* UNITS_H */
