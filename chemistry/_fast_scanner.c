/*
 * _fast_scanner.c  —  EvilWAF Fast Scanner C Extension
 * Python C API extension for high-performance WAF scanning.

 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>



#define MAX_BODY      8192
#define MAX_HDR_LEN   4096
#define MAX_STR       512
#define BLOCK_CODES_N 10
#define CHALL_CODES_N 3

static const int BLOCK_CODES[BLOCK_CODES_N]  = {400,403,405,406,429,444,503,502,508,520};
static const int CHALL_CODES[CHALL_CODES_N]  = {401,407,503};

/* block/challenge keyword tables */
static const char *BLOCK_KW[] = {
    "blocked","forbidden","access denied","request rejected",
    "security violation","attack detected","waf","firewall",
    "not acceptable","bad request","illegal","threat detected",
    "access control","protection","denied","violation",
    NULL
};
static const char *CHALL_KW[] = {
    "challenge","captcha","verify","human","robot","cloudflare",
    "just a moment","checking your browser","turnstile",
    NULL
};
static const char *BLOCK_HDRS[] = {
    "x-waf-block","x-firewall","cf-mitigated","x-sucuri-block",
    "x-iinfo","x-denied","server-timing",
    NULL
};



static void str_lower(char *dst, const char *src, size_t max) {
    size_t i = 0;
    for (; src[i] && i < max - 1; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

static int str_contains(const char *haystack, const char *needle) {
    return strstr(haystack, needle) != NULL;
}

static int code_in(int code, const int *arr, int n) {
    for (int i = 0; i < n; i++)
        if (arr[i] == code) return 1;
    return 0;
}



/*
 * classify_response(status: int, body: str, headers_json: str) -> str
 * Returns "passed" | "blocked" | "challenge" | "error" | "timeout"
 */
static PyObject *py_classify_response(PyObject *self, PyObject *args) {
    int         status;
    const char *body_raw;
    const char *hdrs_raw;

    if (!PyArg_ParseTuple(args, "iss", &status, &body_raw, &hdrs_raw))
        return NULL;

    char body[MAX_BODY];
    char hdrs[MAX_HDR_LEN];
    str_lower(body, body_raw, MAX_BODY);
    str_lower(hdrs, hdrs_raw, MAX_HDR_LEN);

    /* challenge keywords in body */
    for (int i = 0; CHALL_KW[i]; i++)
        if (str_contains(body, CHALL_KW[i]))
            return PyUnicode_FromString("challenge");

    /* challenge status + www-authenticate */
    if (code_in(status, CHALL_CODES, CHALL_CODES_N) &&
        str_contains(hdrs, "www-authenticate"))
        return PyUnicode_FromString("challenge");

    /* block headers */
    for (int i = 0; BLOCK_HDRS[i]; i++)
        if (str_contains(hdrs, BLOCK_HDRS[i]))
            return PyUnicode_FromString("blocked");

    /* block status codes */
    if (code_in(status, BLOCK_CODES, BLOCK_CODES_N))
        return PyUnicode_FromString("blocked");

    /* block keywords in body */
    for (int i = 0; BLOCK_KW[i]; i++)
        if (str_contains(body, BLOCK_KW[i]))
            return PyUnicode_FromString("blocked");

    /* pass */
    if (status >= 200 && status < 400)
        return PyUnicode_FromString("passed");

    return PyUnicode_FromString("blocked");
}



/*
 * batch_classify(records: list[tuple(int,str,str)]) -> list[str]
 * Classifies a batch of (status, body, headers_json) tuples.
 */
static PyObject *py_batch_classify(PyObject *self, PyObject *args) {
    PyObject *records;
    if (!PyArg_ParseTuple(args, "O!", &PyList_Type, &records))
        return NULL;

    Py_ssize_t n   = PyList_GET_SIZE(records);
    PyObject  *out = PyList_New(n);
    if (!out) return NULL;

    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *item = PyList_GET_ITEM(records, i);
        if (!PyTuple_Check(item) || PyTuple_GET_SIZE(item) != 3) {
            PyList_SET_ITEM(out, i, PyUnicode_FromString("error"));
            continue;
        }
        int         status = (int)PyLong_AsLong(PyTuple_GET_ITEM(item, 0));
        const char *body   = PyUnicode_AsUTF8(PyTuple_GET_ITEM(item, 1));
        const char *hdrs   = PyUnicode_AsUTF8(PyTuple_GET_ITEM(item, 2));
        if (!body || !hdrs) {
            PyList_SET_ITEM(out, i, PyUnicode_FromString("error"));
            continue;
        }
        PyObject *single_args = Py_BuildValue("(iss)", status, body, hdrs);
        PyObject *result      = py_classify_response(self, single_args);
        Py_DECREF(single_args);
        PyList_SET_ITEM(out, i, result ? result : PyUnicode_FromString("error"));
    }
    return out;
}



/*
 * compute_entropy(data: str) -> float
 * Shannon entropy of a string — useful for detecting obfuscated payloads
 * and WAF bypass encoding patterns.
 */
static PyObject *py_compute_entropy(PyObject *self, PyObject *args) {
    const char *data;
    Py_ssize_t  len;
    if (!PyArg_ParseTuple(args, "s#", &data, &len))
        return NULL;
    if (len == 0)
        return PyFloat_FromDouble(0.0);

    uint64_t freq[256] = {0};
    for (Py_ssize_t i = 0; i < len; i++)
        freq[(unsigned char)data[i]]++;

    double entropy = 0.0;
    double flen    = (double)len;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p  = freq[i] / flen;
        entropy  -= p * log2(p);
    }
    return PyFloat_FromDouble(entropy);
}



/*
 * levenshtein(a: str, b: str) -> int
 * Edit distance — used to detect near-duplicate responses (WAF fingerprinting).
 */
static PyObject *py_levenshtein(PyObject *self, PyObject *args) {
    const char *a, *b;
    Py_ssize_t  la, lb;
    if (!PyArg_ParseTuple(args, "s#s#", &a, &la, &b, &lb))
        return NULL;

    /* cap at 512 chars for speed */
    if (la > 512) la = 512;
    if (lb > 512) lb = 512;

    /* allocate two rows */
    int *prev = (int *)malloc((lb + 1) * sizeof(int));
    int *curr = (int *)malloc((lb + 1) * sizeof(int));
    if (!prev || !curr) {
        free(prev); free(curr);
        PyErr_NoMemory();
        return NULL;
    }
    for (Py_ssize_t j = 0; j <= lb; j++) prev[j] = (int)j;

    for (Py_ssize_t i = 1; i <= la; i++) {
        curr[0] = (int)i;
        for (Py_ssize_t j = 1; j <= lb; j++) {
            int cost  = (a[i-1] == b[j-1]) ? 0 : 1;
            int del   = prev[j]   + 1;
            int ins   = curr[j-1] + 1;
            int sub   = prev[j-1] + cost;
            curr[j]   = del < ins ? (del < sub ? del : sub)
                                  : (ins < sub ? ins : sub);
        }
        int *tmp = prev; prev = curr; curr = tmp;
    }
    int dist = prev[lb];
    free(prev); free(curr);
    return PyLong_FromLong(dist);
}



/*
 * fingerprint_response(body: str, headers_json: str) -> dict
 * Extracts structural fingerprint of a WAF response for clustering.
 * Returns: {entropy, body_len, has_cf_ray, has_captcha,
 *           has_block_kw, has_chall_kw, status_class}
 */
static PyObject *py_fingerprint_response(PyObject *self, PyObject *args) {
    const char *body_raw;
    const char *hdrs_raw;
    if (!PyArg_ParseTuple(args, "ss", &body_raw, &hdrs_raw))
        return NULL;

    char body[MAX_BODY];
    char hdrs[MAX_HDR_LEN];
    str_lower(body, body_raw, MAX_BODY);
    str_lower(hdrs, hdrs_raw, MAX_HDR_LEN);

    /* entropy of body */
    Py_ssize_t blen    = (Py_ssize_t)strlen(body_raw);
    uint64_t   freq[256] = {0};
    for (Py_ssize_t i = 0; i < blen && i < MAX_BODY; i++)
        freq[(unsigned char)body_raw[i]]++;
    double entropy = 0.0;
    if (blen > 0) {
        double flen = (double)blen;
        for (int i = 0; i < 256; i++) {
            if (!freq[i]) continue;
            double p  = freq[i] / flen;
            entropy  -= p * log2(p);
        }
    }

    int has_cf_ray   = str_contains(hdrs, "cf-ray");
    int has_captcha  = str_contains(body, "captcha") || str_contains(body, "turnstile");
    int has_block    = 0;
    int has_chall    = 0;

    for (int i = 0; BLOCK_KW[i]; i++)
        if (str_contains(body, BLOCK_KW[i])) { has_block = 1; break; }
    for (int i = 0; CHALL_KW[i]; i++)
        if (str_contains(body, CHALL_KW[i])) { has_chall = 1; break; }

    PyObject *d = PyDict_New();
    if (!d) return NULL;
    PyDict_SetItemString(d, "entropy",       PyFloat_FromDouble(entropy));
    PyDict_SetItemString(d, "body_len",      PyLong_FromSsize_t(blen));
    PyDict_SetItemString(d, "has_cf_ray",    PyBool_FromLong(has_cf_ray));
    PyDict_SetItemString(d, "has_captcha",   PyBool_FromLong(has_captcha));
    PyDict_SetItemString(d, "has_block_kw",  PyBool_FromLong(has_block));
    PyDict_SetItemString(d, "has_chall_kw",  PyBool_FromLong(has_chall));
    return d;
}



/*
 * rolling_stats(values: list[float]) -> dict
 * Fast mean/std/min/max/p50/p95/p99 — replaces numpy in hot paths.
 */
static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static PyObject *py_rolling_stats(PyObject *self, PyObject *args) {
    PyObject *lst;
    if (!PyArg_ParseTuple(args, "O!", &PyList_Type, &lst))
        return NULL;

    Py_ssize_t n = PyList_GET_SIZE(lst);
    if (n == 0) {
        PyObject *d = PyDict_New();
        PyDict_SetItemString(d, "mean", PyFloat_FromDouble(0.0));
        PyDict_SetItemString(d, "std",  PyFloat_FromDouble(0.0));
        PyDict_SetItemString(d, "min",  PyFloat_FromDouble(0.0));
        PyDict_SetItemString(d, "max",  PyFloat_FromDouble(0.0));
        PyDict_SetItemString(d, "p50",  PyFloat_FromDouble(0.0));
        PyDict_SetItemString(d, "p95",  PyFloat_FromDouble(0.0));
        PyDict_SetItemString(d, "p99",  PyFloat_FromDouble(0.0));
        return d;
    }

    double *arr = (double *)malloc(n * sizeof(double));
    if (!arr) { PyErr_NoMemory(); return NULL; }

    double sum = 0.0;
    for (Py_ssize_t i = 0; i < n; i++) {
        arr[i] = PyFloat_AsDouble(PyList_GET_ITEM(lst, i));
        sum   += arr[i];
    }
    double mean = sum / n;

    double var = 0.0;
    for (Py_ssize_t i = 0; i < n; i++) {
        double d = arr[i] - mean;
        var += d * d;
    }
    double std = sqrt(var / n);

    qsort(arr, n, sizeof(double), cmp_double);
    double mn  = arr[0];
    double mx  = arr[n - 1];
    double p50 = arr[(Py_ssize_t)(n * 0.50)];
    double p95 = arr[(Py_ssize_t)(n * 0.95 < n - 1 ? n * 0.95 : n - 1)];
    double p99 = arr[(Py_ssize_t)(n * 0.99 < n - 1 ? n * 0.99 : n - 1)];
    free(arr);

    PyObject *d = PyDict_New();
    if (!d) return NULL;
    PyDict_SetItemString(d, "mean", PyFloat_FromDouble(mean));
    PyDict_SetItemString(d, "std",  PyFloat_FromDouble(std));
    PyDict_SetItemString(d, "min",  PyFloat_FromDouble(mn));
    PyDict_SetItemString(d, "max",  PyFloat_FromDouble(mx));
    PyDict_SetItemString(d, "p50",  PyFloat_FromDouble(p50));
    PyDict_SetItemString(d, "p95",  PyFloat_FromDouble(p95));
    PyDict_SetItemString(d, "p99",  PyFloat_FromDouble(p99));
    return d;
}



/*
 * detect_timing_anomaly(times: list[float], baseline_ms: float) -> dict
 * Detects timing-based WAF behaviour (e.g. Cloudflare JS challenge delays,
 * Returns: {anomaly: bool, score: float, mean_ms, delta_ms, pattern: str}
 */
static PyObject *py_detect_timing_anomaly(PyObject *self, PyObject *args) {
    PyObject *lst;
    double    baseline_ms;
    if (!PyArg_ParseTuple(args, "O!d", &PyList_Type, &lst, &baseline_ms))
        return NULL;

    Py_ssize_t n = PyList_GET_SIZE(lst);
    if (n < 3) {
        PyObject *d = PyDict_New();
        PyDict_SetItemString(d, "anomaly", Py_False);
        PyDict_SetItemString(d, "score",   PyFloat_FromDouble(0.0));
        PyDict_SetItemString(d, "pattern", PyUnicode_FromString("insufficient_data"));
        return d;
    }

    double *arr = (double *)malloc(n * sizeof(double));
    if (!arr) { PyErr_NoMemory(); return NULL; }

    double sum = 0.0;
    for (Py_ssize_t i = 0; i < n; i++) {
        arr[i]  = PyFloat_AsDouble(PyList_GET_ITEM(lst, i)) * 1000.0; /* to ms */
        sum    += arr[i];
    }
    double mean = sum / n;

    double var = 0.0;
    for (Py_ssize_t i = 0; i < n; i++) {
        double d = arr[i] - mean;
        var += d * d;
    }
    double std   = sqrt(var / n);
    double delta = mean - baseline_ms;

    /* detect monotonic increase (tar-pit / rate-limit back-off) */
    int monotone = 1;
    for (Py_ssize_t i = 1; i < n; i++)
        if (arr[i] < arr[i-1] - 5.0) { monotone = 0; break; }

    /* detect bimodal  */
    int bimodal = 0;
    int fast = 0, slow = 0;
    for (Py_ssize_t i = 0; i < n; i++) {
        if (arr[i] < mean * 0.5) fast++;
        if (arr[i] > mean * 1.5) slow++;
    }
    if (fast > n / 4 && slow > n / 4) bimodal = 1;

    free(arr);

    double score  = 0.0;
    const char *pattern = "normal";

    if (delta > 500.0)  { score += 0.4; pattern = "high_latency"; }
    if (delta > 2000.0) { score += 0.3; pattern = "tarpit"; }
    if (monotone)       { score += 0.3; pattern = "backoff"; }
    if (bimodal)        { score += 0.2; pattern = "bimodal_challenge"; }
    if (std > mean)     { score += 0.1; pattern = "jitter"; }
    if (score > 1.0)      score = 1.0;

    int anomaly = score >= 0.35;

    PyObject *d = PyDict_New();
    if (!d) return NULL;
    PyDict_SetItemString(d, "anomaly",   PyBool_FromLong(anomaly));
    PyDict_SetItemString(d, "score",     PyFloat_FromDouble(score));
    PyDict_SetItemString(d, "mean_ms",   PyFloat_FromDouble(mean));
    PyDict_SetItemString(d, "delta_ms",  PyFloat_FromDouble(delta));
    PyDict_SetItemString(d, "std_ms",    PyFloat_FromDouble(std));
    PyDict_SetItemString(d, "pattern",   PyUnicode_FromString(pattern));
    return d;
}



static PyMethodDef FastScannerMethods[] = {
    {"classify_response",    py_classify_response,    METH_VARARGS,
     "classify_response(status, body, headers_json) -> str\n"
     "Classify HTTP response outcome: passed/blocked/challenge/error"},
    {"batch_classify",       py_batch_classify,       METH_VARARGS,
     "batch_classify(records) -> list[str]\n"
     "Batch classify list of (status, body, headers_json) tuples"},
    {"compute_entropy",      py_compute_entropy,      METH_VARARGS,
     "compute_entropy(data) -> float\n"
     "Shannon entropy of a string"},
    {"levenshtein",          py_levenshtein,          METH_VARARGS,
     "levenshtein(a, b) -> int\n"
     "Edit distance between two strings (capped at 512 chars)"},
    {"fingerprint_response", py_fingerprint_response, METH_VARARGS,
     "fingerprint_response(body, headers_json) -> dict\n"
     "Structural fingerprint of a WAF response"},
    {"rolling_stats",        py_rolling_stats,        METH_VARARGS,
     "rolling_stats(values) -> dict\n"
     "Fast descriptive statistics: mean/std/min/max/p50/p95/p99"},
    {"detect_timing_anomaly",py_detect_timing_anomaly,METH_VARARGS,
     "detect_timing_anomaly(times, baseline_ms) -> dict\n"
     "Detect WAF timing anomalies: tarpit/backoff/bimodal/jitter"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef FastScannerModule = {
    PyModuleDef_HEAD_INIT,
    "_fast_scanner",
    "EvilWAF C extension — high-performance response classification & analysis",
    -1,
    FastScannerMethods
};

PyMODINIT_FUNC PyInit__fast_scanner(void) {
    return PyModule_Create(&FastScannerModule);
}