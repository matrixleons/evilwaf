#include "tls_prober.h"
#include "ip_classifier.h"
#include "tcp_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define CLOSE_SOCKET(s) closesocket(s)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <pthread.h>
    #define CLOSE_SOCKET(s) close(s)
#endif

static long long ms_now_tls(void) {
    struct timespec ts;
#ifdef _WIN32
    timespec_get(&ts, TIME_UTC);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static void do_tls_probe(TlsTask *t) {
    long long t0  = ms_now_tls();
    int lat        = tcp_connect_ms(t->ip, t->port, 4000);
    t->latency_ms  = ms_now_tls() - t0;

    if (lat < 0) {
        t->reachable = 0;
        return;
    }
    t->reachable = 1;

    int waf = is_waf_ip(t->ip);
    t->is_cf       = waf;
    t->cert_matches = (!waf);
    t->ip_category  = classify_ip(t->ip);
}

#ifndef _WIN32
static void *tls_thread(void *arg) {
    do_tls_probe((TlsTask *)arg);
    return NULL;
}
#else
static unsigned __stdcall tls_thread(void *arg) {
    do_tls_probe((TlsTask *)arg);
    return 0;
}
#endif

int tls_probe_batch(TlsTask *tasks, int count) {
    if (count <= 0 || count > TLS_MAX_BATCH) return -1;
#ifndef _WIN32
    pthread_t *tids = calloc(count, sizeof(pthread_t));
    if (!tids) return -1;
    for (int i = 0; i < count; i++)
        pthread_create(&tids[i], NULL, tls_thread, &tasks[i]);
    for (int i = 0; i < count; i++)
        pthread_join(tids[i], NULL);
    free(tids);
#else
    HANDLE *handles = calloc(count, sizeof(HANDLE));
    if (!handles) return -1;
    for (int i = 0; i < count; i++)
        handles[i] = (HANDLE)_beginthreadex(
            NULL, 0, tls_thread, &tasks[i], 0, NULL);
    WaitForMultipleObjects(count, handles, TRUE, 10000);
    for (int i = 0; i < count; i++) CloseHandle(handles[i]);
    free(handles);
#endif
    return count;
}