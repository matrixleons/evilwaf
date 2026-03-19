#include "tcp_scanner.h"
#include "ip_classifier.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define CLOSE_SOCKET(s)      closesocket(s)
    #define SOCK_NONBLOCK_SET(s) do { u_long m=1; ioctlsocket(s,FIONBIO,&m); } while(0)
    #define EINPROGRESS_VAL      WSAEWOULDBLOCK
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <pthread.h>
    #define CLOSE_SOCKET(s)      close(s)
    #define SOCK_NONBLOCK_SET(s) do { \
        int f = fcntl(s, F_GETFL, 0); fcntl(s, F_SETFL, f | O_NONBLOCK); } while(0)
    #define EINPROGRESS_VAL      EINPROGRESS
#endif

static long long ms_now(void) {
    struct timespec ts;
#ifdef _WIN32
    timespec_get(&ts, TIME_UTC);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

int tcp_connect_ms(const char *host, int port, int timeout_ms) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
        return -1;
    int s = (int)socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) { freeaddrinfo(res); return -1; }
#ifndef _WIN32
    int flag = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
#endif
    SOCK_NONBLOCK_SET(s);
    long long t0 = ms_now();
    connect(s, res->ai_addr, (socklen_t)res->ai_addrlen);
    freeaddrinfo(res);
    fd_set wfds, efds;
    FD_ZERO(&wfds); FD_ZERO(&efds);
    FD_SET((unsigned)s, &wfds);
    FD_SET((unsigned)s, &efds);
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int sel = select(s + 1, NULL, &wfds, &efds, &tv);
    if (sel <= 0 || FD_ISSET((unsigned)s, &efds)) {
        CLOSE_SOCKET(s); return -1;
    }
    int err = 0; socklen_t len = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
    CLOSE_SOCKET(s);
    if (err != 0) return -1;
    return (int)(ms_now() - t0);
}

#ifndef _WIN32
static void *tcp_thread(void *arg) {
    TcpTask *t   = (TcpTask *)arg;
    t->result_ms = tcp_connect_ms(t->host, t->port, t->timeout_ms);
    return NULL;
}
#else
static unsigned __stdcall tcp_thread(void *arg) {
    TcpTask *t   = (TcpTask *)arg;
    t->result_ms = tcp_connect_ms(t->host, t->port, t->timeout_ms);
    return 0;
}
#endif

int parallel_tcp_scan(TcpTask *tasks, int count) {
    if (count <= 0 || count > TCP_MAX_BATCH) return -1;
#ifndef _WIN32
    pthread_t *tids = calloc(count, sizeof(pthread_t));
    if (!tids) return -1;
    for (int i = 0; i < count; i++)
        pthread_create(&tids[i], NULL, tcp_thread, &tasks[i]);
    for (int i = 0; i < count; i++)
        pthread_join(tids[i], NULL);
    free(tids);
#else
    HANDLE *handles = calloc(count, sizeof(HANDLE));
    if (!handles) return -1;
    for (int i = 0; i < count; i++)
        handles[i] = (HANDLE)_beginthreadex(
            NULL, 0, tcp_thread, &tasks[i], 0, NULL);
    WaitForMultipleObjects(count, handles, TRUE, tasks[0].timeout_ms + 2000);
    for (int i = 0; i < count; i++) CloseHandle(handles[i]);
    free(handles);
#endif
    return count;
}