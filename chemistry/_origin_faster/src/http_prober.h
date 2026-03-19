#ifndef HTTP_PROBER_H
#define HTTP_PROBER_H

#define HTTP_MAX_BATCH  2000
#define HTTP_BUF_SIZE   16384

typedef struct {
    char      ip[64];
    char      domain[256];
    int       port;
    int       reachable;
    int       status_code;
    int       is_cf;
    int       is_cdn;
    char      server_header[128];
    char      origin_hints[512];
    long long latency_ms;
} HttpTask;

int http_probe_batch(HttpTask *tasks, int count);

#endif