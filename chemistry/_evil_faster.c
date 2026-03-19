#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
    #define CLOSE_SOCKET(s) closesocket(s)
    #define GET_ERROR WSAGetLastError()
    #define SOCK_NONBLOCK_SET(s) do { \
        u_long mode = 1; \
        ioctlsocket(s, FIONBIO, &mode); \
    } while(0)
    #define SOCK_BLOCK_SET(s) do { \
        u_long mode = 0; \
        ioctlsocket(s, FIONBIO, &mode); \
    } while(0)
    #define EINPROGRESS_VAL WSAEWOULDBLOCK
    static void platform_init(void) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <netdb.h>
    #define CLOSE_SOCKET(s) close(s)
    #define GET_ERROR errno
    #define SOCK_NONBLOCK_SET(s) do { \
        int flags = fcntl(s, F_GETFL, 0); \
        fcntl(s, F_SETFL, flags | O_NONBLOCK); \
    } while(0)
    #define SOCK_BLOCK_SET(s) do { \
        int flags = fcntl(s, F_GETFL, 0); \
        fcntl(s, F_SETFL, flags & ~O_NONBLOCK); \
    } while(0)
    #define EINPROGRESS_VAL EINPROGRESS
    static void platform_init(void) {}
#endif

static long long get_time_ms(void) {
    struct timespec ts;
#ifdef _WIN32
    timespec_get(&ts, TIME_UTC);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return (long long)ts.tv_sec * 1000LL + (long long)ts.tv_nsec / 1000000LL;
}

int tcp_connect_test(const char *host, int port, int timeout_ms) {
    platform_init();

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || res == NULL) {
        return -1;
    }

    int sock = (int)socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        return -1;
    }

    int flag = 1;
#ifndef _WIN32
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
#endif

    SOCK_NONBLOCK_SET(sock);

    long long t_start = get_time_ms();
    int result = connect(sock, res->ai_addr, (socklen_t)res->ai_addrlen);
    freeaddrinfo(res);

    if (result == 0) {
        long long elapsed = get_time_ms() - t_start;
        CLOSE_SOCKET(sock);
        return (int)elapsed;
    }

    if (GET_ERROR != EINPROGRESS_VAL) {
        CLOSE_SOCKET(sock);
        return -1;
    }

    fd_set wfds, efds;
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    FD_SET((unsigned)sock, &wfds);
    FD_SET((unsigned)sock, &efds);

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel = select(sock + 1, NULL, &wfds, &efds, &tv);

    if (sel <= 0) {
        CLOSE_SOCKET(sock);
        return -1;
    }

    if (FD_ISSET((unsigned)sock, &efds)) {
        CLOSE_SOCKET(sock);
        return -1;
    }

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len);

    CLOSE_SOCKET(sock);

    if (err != 0) {
        return -1;
    }

    long long elapsed = get_time_ms() - t_start;
    return (int)elapsed;
}

typedef struct {
    const char *host;
    int         port;
    int         timeout_ms;
    int         result_ms;
} BatchEntry;

#ifdef _WIN32
#include <process.h>
typedef HANDLE thread_t;
static unsigned __stdcall batch_worker(void *arg) {
    BatchEntry *e = (BatchEntry *)arg;
    e->result_ms  = tcp_connect_test(e->host, e->port, e->timeout_ms);
    return 0;
}
static thread_t thread_create(BatchEntry *e) {
    return (HANDLE)_beginthreadex(NULL, 0, batch_worker, e, 0, NULL);
}
static void thread_join(thread_t t) {
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
}
#else
#include <pthread.h>
typedef pthread_t thread_t;
static void *batch_worker(void *arg) {
    BatchEntry *e = (BatchEntry *)arg;
    e->result_ms  = tcp_connect_test(e->host, e->port, e->timeout_ms);
    return NULL;
}
static thread_t thread_create(BatchEntry *e) {
    thread_t t;
    if (pthread_create(&t, NULL, batch_worker, e) != 0) {
        e->result_ms = -1;
        return (thread_t)0;
    }
    return t;
}
static void thread_join(thread_t t) {
    if (t) pthread_join(t, NULL);
}
#endif

#define MAX_BATCH 1024

int batch_tcp_test(
    const char **hosts,
    const int   *ports,
    int          count,
    int          timeout_ms,
    int         *results
) {
    if (count <= 0 || count > MAX_BATCH) return -1;

    BatchEntry *entries = (BatchEntry *)calloc(count, sizeof(BatchEntry));
    thread_t   *threads = (thread_t   *)calloc(count, sizeof(thread_t));

    if (!entries || !threads) {
        free(entries);
        free(threads);
        return -1;
    }

    for (int i = 0; i < count; i++) {
        entries[i].host       = hosts[i];
        entries[i].port       = ports[i];
        entries[i].timeout_ms = timeout_ms;
        entries[i].result_ms  = -1;
        threads[i]            = thread_create(&entries[i]);
    }

    for (int i = 0; i < count; i++) {
        thread_join(threads[i]);
        results[i] = entries[i].result_ms;
    }

    free(entries);
    free(threads);
    return count;
}