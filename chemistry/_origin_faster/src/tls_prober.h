#ifndef TLS_PROBER_H
#define TLS_PROBER_H

#define TLS_MAX_BATCH 2000

typedef struct {
    char        ip[64];
    char        domain[256];
    int         port;
    int         reachable;
    int         cert_matches;
    int         is_cf;
    const char *ip_category;
    long long   latency_ms;
} TlsTask;

int tls_probe_batch(TlsTask *tasks, int count);

#endif