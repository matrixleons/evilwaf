#include "ip_classifier.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const IpRange WAF_RANGES[] = {
    {"173.245.48.0",  "173.245.63.255",  "cloudflare"},
    {"103.21.244.0",  "103.21.247.255",  "cloudflare"},
    {"103.22.200.0",  "103.22.203.255",  "cloudflare"},
    {"103.31.4.0",    "103.31.7.255",    "cloudflare"},
    {"141.101.64.0",  "141.101.127.255", "cloudflare"},
    {"108.162.192.0", "108.162.255.255", "cloudflare"},
    {"190.93.240.0",  "190.93.255.255",  "cloudflare"},
    {"188.114.96.0",  "188.114.111.255", "cloudflare"},
    {"197.234.240.0", "197.234.243.255", "cloudflare"},
    {"198.41.128.0",  "198.41.255.255",  "cloudflare"},
    {"162.158.0.0",   "162.159.255.255", "cloudflare"},
    {"104.16.0.0",    "104.23.255.255",  "cloudflare"},
    {"104.24.0.0",    "104.27.255.255",  "cloudflare"},
    {"172.64.0.0",    "172.71.255.255",  "cloudflare"},
    {"131.0.72.0",    "131.0.75.255",    "cloudflare"},
    {"23.235.32.0",   "23.235.47.255",   "fastly"},
    {"151.101.0.0",   "151.101.255.255", "fastly"},
    {"199.232.0.0",   "199.233.255.255", "fastly"},
    {"157.52.64.0",   "157.52.127.255",  "fastly"},
    {"167.82.0.0",    "167.82.127.255",  "fastly"},
    {"72.246.0.0",    "72.247.255.255",  "akamai"},
    {"88.221.0.0",    "88.221.255.255",  "akamai"},
    {"92.122.0.0",    "92.123.255.255",  "akamai"},
    {"95.100.0.0",    "95.101.255.255",  "akamai"},
    {"184.24.0.0",    "184.31.255.255",  "akamai"},
    {"23.32.0.0",     "23.63.255.255",   "akamai"},
    {"104.64.0.0",    "104.127.255.255", "akamai"},
    {"192.30.0.0",    "192.30.31.255",   "incapsula"},
    {"149.126.72.0",  "149.126.79.255",  "incapsula"},
    {"103.28.248.0",  "103.28.251.255",  "incapsula"},
    {"45.64.64.0",    "45.64.67.255",    "incapsula"},
    {"185.11.124.0",  "185.11.127.255",  "incapsula"},
    {"199.83.128.0",  "199.83.135.255",  "incapsula"},
    {"66.235.200.0",  "66.235.203.255",  "sucuri"},
    {"185.93.228.0",  "185.93.231.255",  "sucuri"},
    {"192.124.249.0", "192.124.249.255", "sucuri"},
    {"192.161.0.0",   "192.161.0.255",   "sucuri"},
    {"13.32.0.0",     "13.33.255.255",   "aws_cloudfront"},
    {"52.84.0.0",     "52.85.255.255",   "aws_cloudfront"},
    {"54.192.0.0",    "54.192.255.255",  "aws_cloudfront"},
    {"54.230.0.0",    "54.230.255.255",  "aws_cloudfront"},
    {"205.251.192.0", "205.251.223.255", "aws_cloudfront"},
    {"34.0.0.0",      "34.127.255.255",  "google_cloud"},
    {"35.0.0.0",      "35.255.255.255",  "google_cloud"},
    {"130.211.0.0",   "130.211.3.255",   "google_cloud"},
    {"40.64.0.0",     "40.127.255.255",  "azure_cdn"},
    {"13.64.0.0",     "13.95.255.255",   "azure_cdn"},
    {"52.0.0.0",      "52.63.255.255",   "datacenter"},
    {"54.0.0.0",      "54.255.255.255",  "datacenter"},
    {"10.0.0.0",      "10.255.255.255",  "private"},
    {"172.16.0.0",    "172.31.255.255",  "private"},
    {"192.168.0.0",   "192.168.255.255", "private"},
    {"100.64.0.0",    "100.127.255.255", "private"},
    {"169.254.0.0",   "169.254.255.255", "private"},
    {"127.0.0.0",     "127.255.255.255", "private"},
    {NULL, NULL, NULL}
};

static const char *CF_HEADER_INDICATORS[] = {
    "cf-ray", "cf-cache-status", "cf-request-id",
    "server: cloudflare", "__cfduid", "cf-connecting-ip",
    "cf-visitor", "cf-ipcountry", "cf-worker",
    NULL
};

unsigned int ip_to_uint(const char *ip) {
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

const char *classify_ip(const char *ip) {
    unsigned int addr = ip_to_uint(ip);
    if (addr == 0) return "unknown";
    for (int i = 0; WAF_RANGES[i].start; i++) {
        if (addr >= ip_to_uint(WAF_RANGES[i].start) &&
            addr <= ip_to_uint(WAF_RANGES[i].end))
            return WAF_RANGES[i].category;
    }
    return "unknown";
}

int is_waf_ip(const char *ip) {
    const char *cat = classify_ip(ip);
    return (strcmp(cat, "unknown") != 0);
}

int is_private_ip(const char *ip) {
    const char *cat = classify_ip(ip);
    return (strcmp(cat, "private") == 0);
}

int has_cf_headers(const char *response_lower) {
    for (int i = 0; CF_HEADER_INDICATORS[i]; i++) {
        if (strstr(response_lower, CF_HEADER_INDICATORS[i]))
            return 1;
    }
    return 0;
}

int classify_batch(const char **ips, int count, IpClassifyResult *out) {
    for (int i = 0; i < count; i++) {
        strncpy(out[i].ip, ips[i], 63);
        out[i].ip[63]    = '\0';
        out[i].category  = classify_ip(ips[i]);
        out[i].is_waf    = is_waf_ip(ips[i]);
        out[i].is_private = is_private_ip(ips[i]);
    }
    return count;
}