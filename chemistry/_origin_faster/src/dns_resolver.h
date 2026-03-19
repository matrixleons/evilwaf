#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#define DNS_MAX_BATCH   2000
#define DNS_TIMEOUT_MS  4000

typedef struct {
    char hostname[256];
    char result_ip[64];
    int  resolved;
    int  is_waf;
} DnsTask;

int parallel_dns_resolve(DnsTask *tasks, int count, int filter_waf);
int axfr_attempt(const char *domain, const char **nameservers,
                 int ns_count, char **out_ips, int max_out);

#endif