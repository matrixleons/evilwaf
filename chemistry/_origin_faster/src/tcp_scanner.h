#ifndef TCP_SCANNER_H
#define TCP_SCANNER_H

#define TCP_MAX_BATCH  4096
#define TCP_DEF_TIMEOUT 2000

typedef struct {
    char host[256];
    int  port;
    int  timeout_ms;
    int  result_ms;
} TcpTask;

int tcp_connect_ms(const char *host, int port, int timeout_ms);
int parallel_tcp_scan(TcpTask *tasks, int count);

#endif