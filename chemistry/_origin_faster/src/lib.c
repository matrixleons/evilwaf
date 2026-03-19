#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <stdlib.h>

#include "ip_classifier.h"
#include "tcp_scanner.h"
#include "dns_resolver.h"
#include "http_prober.h"
#include "tls_prober.h"

#ifdef _WIN32
    #include <winsock2.h>
    static void platform_init(void) { WSADATA w; WSAStartup(MAKEWORD(2,2),&w); }
#else
    static void platform_init(void) {}
#endif


static PyObject *py_parallel_tcp_scan(PyObject *self, PyObject *args) {
    PyObject *ip_list, *port_list = NULL;
    int timeout_ms = TCP_DEF_TIMEOUT;
    if (!PyArg_ParseTuple(args, "O|Oi", &ip_list, &port_list, &timeout_ms))
        return NULL;

    int ports[16] = {80, 443, 8080, 8443};
    int nports    = 4;
    if (port_list && PyList_Check(port_list)) {
        nports = (int)PyList_Size(port_list);
        if (nports > 16) nports = 16;
        for (int i = 0; i < nports; i++)
            ports[i] = (int)PyLong_AsLong(PyList_GetItem(port_list, i));
    }

    int nips  = (int)PyList_Size(ip_list);
    int total = nips * nports;
    if (total > TCP_MAX_BATCH) total = TCP_MAX_BATCH;

    TcpTask *tasks    = calloc(total, sizeof(TcpTask));
    char   **ip_strs  = calloc(total, sizeof(char *));
    if (!tasks || !ip_strs) {
        free(tasks); free(ip_strs);
        PyErr_NoMemory(); return NULL;
    }

    int n = 0;
    for (int i = 0; i < nips && n < total; i++) {
        const char *ip = PyUnicode_AsUTF8(PyList_GetItem(ip_list, i));
        if (!ip) continue;
        for (int j = 0; j < nports && n < total; j++, n++) {
            ip_strs[n] = strdup(ip);
            strncpy(tasks[n].host, ip_strs[n], 255);
            tasks[n].port       = ports[j];
            tasks[n].timeout_ms = timeout_ms;
            tasks[n].result_ms  = -1;
        }
    }

    parallel_tcp_scan(tasks, n);

    PyObject *result = PyList_New(0);
    for (int i = 0; i < n; i++) {
        if (tasks[i].result_ms >= 0) {
            PyObject *row = PyTuple_Pack(3,
                PyUnicode_FromString(tasks[i].host),
                PyLong_FromLong(tasks[i].port),
                PyLong_FromLong(tasks[i].result_ms));
            PyList_Append(result, row);
            Py_DECREF(row);
        }
        free(ip_strs[i]);
    }
    free(tasks); free(ip_strs);
    return result;
}


static PyObject *py_parallel_dns_resolve(PyObject *self, PyObject *args) {
    PyObject *hostnames;
    int filter_waf = 1;
    if (!PyArg_ParseTuple(args, "O|i", &hostnames, &filter_waf))
        return NULL;

    int n = (int)PyList_Size(hostnames);
    if (n > DNS_MAX_BATCH) n = DNS_MAX_BATCH;

    DnsTask *tasks = calloc(n, sizeof(DnsTask));
    if (!tasks) { PyErr_NoMemory(); return NULL; }

    for (int i = 0; i < n; i++) {
        const char *h = PyUnicode_AsUTF8(PyList_GetItem(hostnames, i));
        if (h) strncpy(tasks[i].hostname, h, 255);
    }

    parallel_dns_resolve(tasks, n, filter_waf);

    PyObject *result = PyList_New(0);
    for (int i = 0; i < n; i++) {
        if (!tasks[i].resolved) continue;
        PyObject *ip_list = PyList_New(1);
        PyList_SetItem(ip_list, 0, PyUnicode_FromString(tasks[i].result_ip));
        PyObject *row = PyTuple_Pack(2,
            PyUnicode_FromString(tasks[i].hostname),
            ip_list);
        PyList_Append(result, row);
        Py_DECREF(row);
        Py_DECREF(ip_list);
    }
    free(tasks);
    return result;
}


static PyObject *py_ip_classify_batch(PyObject *self, PyObject *args) {
    PyObject *ip_list;
    if (!PyArg_ParseTuple(args, "O", &ip_list)) return NULL;

    int n = (int)PyList_Size(ip_list);
    PyObject *result = PyList_New(0);

    for (int i = 0; i < n; i++) {
        const char *ip  = PyUnicode_AsUTF8(PyList_GetItem(ip_list, i));
        if (!ip) continue;
        const char *cat = classify_ip(ip);
        int         waf = is_waf_ip(ip);
        PyObject *row   = PyTuple_Pack(3,
            PyUnicode_FromString(ip),
            PyUnicode_FromString(cat),
            PyBool_FromLong(waf));
        PyList_Append(result, row);
        Py_DECREF(row);
    }
    return result;
}


static PyObject *py_is_waf_ip(PyObject *self, PyObject *args) {
    const char *ip;
    if (!PyArg_ParseTuple(args, "s", &ip)) return NULL;
    int         waf = is_waf_ip(ip);
    const char *cat = classify_ip(ip);
    return PyTuple_Pack(2,
        PyBool_FromLong(waf),
        PyUnicode_FromString(cat));
}


static PyObject *py_http_probe_batch(PyObject *self, PyObject *args) {
    PyObject   *ip_list;
    const char *domain;
    PyObject   *port_list = NULL;
    if (!PyArg_ParseTuple(args, "Os|O", &ip_list, &domain, &port_list))
        return NULL;

    int ports[8]  = {80, 443, 8080, 8443};
    int nports    = 4;
    if (port_list && PyList_Check(port_list)) {
        nports = (int)PyList_Size(port_list);
        if (nports > 8) nports = 8;
        for (int i = 0; i < nports; i++)
            ports[i] = (int)PyLong_AsLong(PyList_GetItem(port_list, i));
    }

    int nips  = (int)PyList_Size(ip_list);
    int total = nips * nports;
    if (total > HTTP_MAX_BATCH) total = HTTP_MAX_BATCH;

    HttpTask *tasks = calloc(total, sizeof(HttpTask));
    if (!tasks) { PyErr_NoMemory(); return NULL; }

    int n = 0;
    for (int i = 0; i < nips && n < total; i++) {
        const char *ip = PyUnicode_AsUTF8(PyList_GetItem(ip_list, i));
        if (!ip) continue;
        for (int j = 0; j < nports && n < total; j++, n++) {
            strncpy(tasks[n].ip,     ip,     63);
            strncpy(tasks[n].domain, domain, 255);
            tasks[n].port = ports[j];
        }
    }

    http_probe_batch(tasks, n);

    PyObject *result = PyList_New(0);
    for (int i = 0; i < n; i++) {
        if (!tasks[i].reachable || tasks[i].is_cf) continue;
        PyObject *hints = PyList_New(0);
        if (tasks[i].origin_hints[0]) {
            PyList_Append(hints, PyUnicode_FromString(tasks[i].origin_hints));
        }
        PyObject *srv = tasks[i].server_header[0]
            ? PyUnicode_FromString(tasks[i].server_header)
            : (Py_INCREF(Py_None), Py_None);
        PyObject *row = PyTuple_Pack(10,
            PyUnicode_FromString(tasks[i].ip),
            PyLong_FromLong(tasks[i].port),
            PyBool_FromLong(tasks[i].reachable),
            PyLong_FromLong(tasks[i].status_code),
            PyBool_FromLong(tasks[i].is_cf),
            PyBool_FromLong(tasks[i].is_cdn),
            hints,
            srv,
            PyUnicode_FromString(classify_ip(tasks[i].ip)),
            PyLong_FromLongLong(tasks[i].latency_ms));
        PyList_Append(result, row);
        Py_DECREF(row);
        Py_DECREF(hints);
    }
    free(tasks);
    return result;
}


static PyObject *py_tls_probe_batch(PyObject *self, PyObject *args) {
    PyObject   *ip_list;
    const char *domain;
    int         port = 443;
    if (!PyArg_ParseTuple(args, "Os|i", &ip_list, &domain, &port))
        return NULL;

    int n = (int)PyList_Size(ip_list);
    if (n > TLS_MAX_BATCH) n = TLS_MAX_BATCH;

    TlsTask *tasks = calloc(n, sizeof(TlsTask));
    if (!tasks) { PyErr_NoMemory(); return NULL; }

    for (int i = 0; i < n; i++) {
        const char *ip = PyUnicode_AsUTF8(PyList_GetItem(ip_list, i));
        if (!ip) continue;
        strncpy(tasks[i].ip,     ip,     63);
        strncpy(tasks[i].domain, domain, 255);
        tasks[i].port = port;
    }

    tls_probe_batch(tasks, n);

    PyObject *result = PyList_New(0);
    for (int i = 0; i < n; i++) {
        PyObject *sans = PyList_New(0);
        PyObject *row  = PyTuple_Pack(9,
            PyUnicode_FromString(tasks[i].ip),
            PyLong_FromLong(tasks[i].port),
            PyBool_FromLong(tasks[i].reachable),
            PyBool_FromLong(tasks[i].cert_matches),
            sans,
            Py_None,
            PyBool_FromLong(tasks[i].is_cf),
            PyUnicode_FromString(
                tasks[i].ip_category ? tasks[i].ip_category : "unknown"),
            PyLong_FromLongLong(tasks[i].latency_ms));
        Py_INCREF(Py_None);
        PyList_Append(result, row);
        Py_DECREF(row);
        Py_DECREF(sans);
    }
    free(tasks);
    return result;
}


static PyObject *py_axfr_attempt(PyObject *self, PyObject *args) {
    const char *domain;
    PyObject   *ns_list;
    if (!PyArg_ParseTuple(args, "sO", &domain, &ns_list))
        return NULL;
    return PyList_New(0);
}


static PyMethodDef OriginMethods[] = {
    {"parallel_tcp_scan",    py_parallel_tcp_scan,    METH_VARARGS, ""},
    {"parallel_dns_resolve", py_parallel_dns_resolve, METH_VARARGS, ""},
    {"ip_classify_batch",    py_ip_classify_batch,    METH_VARARGS, ""},
    {"is_waf_ip",            py_is_waf_ip,            METH_VARARGS, ""},
    {"http_probe_batch",     py_http_probe_batch,     METH_VARARGS, ""},
    {"tls_probe_batch",      py_tls_probe_batch,      METH_VARARGS, ""},
    {"axfr_attempt",         py_axfr_attempt,         METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT, "_origin_faster", NULL, -1, OriginMethods
};

PyMODINIT_FUNC PyInit__origin_faster(void) {
    platform_init();
    return PyModule_Create(&moduledef);
}