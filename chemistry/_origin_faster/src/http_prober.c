#include "http_prober.h"
#include "ip_classifier.h"
#include "tcp_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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

static const char *CDN_INDICATORS[] = {
    "x-cache: hit", "x-served-by", "x-timer",
    "via: 1.1 varnish", "fastly-restarts",
    "x-amz-cf-id", "x-azure-ref",
    "x-akamai", "akamai-origin-hop",
    "x-sucuri-id", "x-sucuri-cache",
    NULL
};

static const char *ORIGIN_HINT_HEADERS[] = {
    "x-powered-by", "x-real-ip", "x-forwarded-server",
    "x-original-url", "x-backend", "x-upstream",
    "x-application-context", "x-generator",
    "x-drupal-cache", "x-nginx-cache",
    NULL
};

static long long ms_now_http(void) {
    struct timespec ts;
#ifdef _WIN32
    timespec_get(&ts, TIME_UTC);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static void str_tolower(const char *src, char *dst, int maxlen) {
    int i;
    for (i = 0; i < maxlen - 1 && src[i]; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

static int parse_status_code(const char *buf) {
    if (strncmp(buf, "HTTP/", 5) != 0) return 0;
    const char *p = strchr(buf, ' ');
    if (!p) return 0;
    return atoi(p + 1);
}

static void extract_header_value(const char *resp_lower,
                                  const char *header,
                                  char *out, int outsz) {
    char *p = strstr(resp_lower, header);
    if (!p) { out[0] = '\0'; return; }
    p += strlen(header);
    while (*p == ':' || *p == ' ') p++;
    int i = 0;
    while (*p && *p != '\r' && *p != '\n' && i < outsz - 1)
        out[i++] = *p++;
    out[i] = '\0';
}

static void do_http_probe(HttpTask *t) {
    long long t0 = ms_now_http();

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", t->port);
    if (getaddrinfo(t->ip, port_str, &hints, &res) != 0 || !res)
        return;

    int sock = (int)socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return; }

    struct timeval tv; tv.tv_sec = 4; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

    if (connect(sock, res->ai_addr, (socklen_t)res->ai_addrlen) != 0) {
        freeaddrinfo(res); CLOSE_SOCKET(sock); return;
    }
    freeaddrinfo(res);
    t->latency_ms = ms_now_http() - t0;
    t->reachable  = 1;

    char req[512];
    snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\nHost: %s\r\n"
        "User-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
        "Connection: close\r\n\r\n",
        t->domain);

    send(sock, req, (int)strlen(req), 0);

    char buf[HTTP_BUF_SIZE];
    int total = 0, n;
    while (total < HTTP_BUF_SIZE - 1) {
        n = recv(sock, buf + total, HTTP_BUF_SIZE - total - 1, 0);
        if (n <= 0) break;
        total += n;
        if (total > 8192) break;
    }
    buf[total] = '\0';
    CLOSE_SOCKET(sock);

    t->status_code = parse_status_code(buf);

    char lower[HTTP_BUF_SIZE];
    str_tolower(buf, lower, HTTP_BUF_SIZE);

    t->is_cf  = has_cf_headers(lower);
    t->is_cdn = t->is_cf || is_waf_ip(t->ip);
    for (int i = 0; CDN_INDICATORS[i]; i++) {
        if (strstr(lower, CDN_INDICATORS[i])) { t->is_cdn = 1; break; }
    }

    extract_header_value(lower, "server", t->server_header,
                         sizeof(t->server_header));

    t->origin_hints[0] = '\0';
    for (int i = 0; ORIGIN_HINT_HEADERS[i]; i++) {
        if (strstr(lower, ORIGIN_HINT_HEADERS[i])) {
            size_t cur = strlen(t->origin_hints);
            size_t rem = sizeof(t->origin_hints) - cur - 1;
            if (rem < 2) break;
            if (cur > 0) {
                t->origin_hints[cur]     = ',';
                t->origin_hints[cur + 1] = '\0';
                cur++;
                rem--;
            }
            strncpy(t->origin_hints + cur, ORIGIN_HINT_HEADERS[i], rem);
            t->origin_hints[sizeof(t->origin_hints) - 1] = '\0';
        }
    }
}

#ifndef _WIN32
static void *http_thread(void *arg) {
    do_http_probe((HttpTask *)arg);
    return NULL;
}
#else
static unsigned __stdcall http_thread(void *arg) {
    do_http_probe((HttpTask *)arg);
    return 0;
}
#endif

int http_probe_batch(HttpTask *tasks, int count) {
    if (count <= 0 || count > HTTP_MAX_BATCH) return -1;
#ifndef _WIN32
    pthread_t *tids = calloc(count, sizeof(pthread_t));
    if (!tids) return -1;
    for (int i = 0; i < count; i++)
        pthread_create(&tids[i], NULL, http_thread, &tasks[i]);
    for (int i = 0; i < count; i++)
        pthread_join(tids[i], NULL);
    free(tids);
#else
    HANDLE *handles = calloc(count, sizeof(HANDLE));
    if (!handles) return -1;
    for (int i = 0; i < count; i++)
        handles[i] = (HANDLE)_beginthreadex(
            NULL, 0, http_thread, &tasks[i], 0, NULL);
    WaitForMultipleObjects(count, handles, TRUE, 10000);
    for (int i = 0; i < count; i++) CloseHandle(handles[i]);
    free(handles);
#endif
    return count;
}