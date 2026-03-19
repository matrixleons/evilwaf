#ifndef IP_CLASSIFIER_H
#define IP_CLASSIFIER_H

typedef struct {
    const char *start;
    const char *end;
    const char *category;
} IpRange;

typedef struct {
    char        ip[64];
    const char *category;
    int         is_waf;
    int         is_private;
} IpClassifyResult;

unsigned int ip_to_uint(const char *ip);
const char  *classify_ip(const char *ip);
int          is_waf_ip(const char *ip);
int          is_private_ip(const char *ip);
int          has_cf_headers(const char *response_lower);
int          classify_batch(const char **ips, int count, IpClassifyResult *out);

#endif