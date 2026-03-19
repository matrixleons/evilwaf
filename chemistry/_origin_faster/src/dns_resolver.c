#include "dns_resolver.h"
#include "ip_classifier.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <pthread.h>
    #include <unistd.h>
#endif

typedef struct {
    char hostname[256];
    char result_ip[64];
    int  filter_waf;
    int  is_waf;
    int  resolved;
} DnsWorkerTask;

#ifndef _WIN32
static void *dns_thread(void *arg) {
    DnsWorkerTask *t = (DnsWorkerTask *)arg;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(t->hostname, NULL, &hints, &res) == 0 && res) {
        struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sa->sin_addr, t->result_ip, sizeof(t->result_ip));
        t->is_waf    = is_waf_ip(t->result_ip);
        t->resolved  = 1;
        freeaddrinfo(res);
    }
    return NULL;
}
#else
static unsigned __stdcall dns_thread(void *arg) {
    DnsWorkerTask *t = (DnsWorkerTask *)arg;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(t->hostname, NULL, &hints, &res) == 0 && res) {
        struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sa->sin_addr, t->result_ip, sizeof(t->result_ip));
        t->is_waf   = is_waf_ip(t->result_ip);
        t->resolved = 1;
        freeaddrinfo(res);
    }
    return 0;
}
#endif

int parallel_dns_resolve(DnsTask *tasks, int count, int filter_waf) {
    if (count <= 0 || count > DNS_MAX_BATCH) return -1;

    DnsWorkerTask *workers = calloc(count, sizeof(DnsWorkerTask));
    if (!workers) return -1;

    for (int i = 0; i < count; i++) {
        strncpy(workers[i].hostname, tasks[i].hostname, 255);
        workers[i].filter_waf = filter_waf;
    }

#ifndef _WIN32
    pthread_t *tids = calloc(count, sizeof(pthread_t));
    if (!tids) { free(workers); return -1; }
    for (int i = 0; i < count; i++)
        pthread_create(&tids[i], NULL, dns_thread, &workers[i]);
    for (int i = 0; i < count; i++)
        pthread_join(tids[i], NULL);
    free(tids);
#else
    HANDLE *handles = calloc(count, sizeof(HANDLE));
    if (!handles) { free(workers); return -1; }
    for (int i = 0; i < count; i++)
        handles[i] = (HANDLE)_beginthreadex(
            NULL, 0, dns_thread, &workers[i], 0, NULL);
    WaitForMultipleObjects(count, handles, TRUE, DNS_TIMEOUT_MS * 2);
    for (int i = 0; i < count; i++) CloseHandle(handles[i]);
    free(handles);
#endif

    int out = 0;
    for (int i = 0; i < count; i++) {
        if (!workers[i].resolved) continue;
        if (filter_waf && workers[i].is_waf) continue;
        strncpy(tasks[i].result_ip, workers[i].result_ip, 63);
        tasks[i].resolved = 1;
        tasks[i].is_waf   = workers[i].is_waf;
        out++;
    }
    free(workers);
    return out;
}

int axfr_attempt(const char *domain, const char **nameservers,
                 int ns_count, char **out_ips, int max_out) {
    (void)domain; (void)nameservers; (void)ns_count;
    (void)out_ips; (void)max_out;
    return 0;
}