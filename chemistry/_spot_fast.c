/* it works with linux , window and macOS */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
  #define CLOSE_SOCK(s) closesocket(s)
  #define GET_ERR       WSAGetLastError()
  #define EADDRINUSE_VAL WSAEADDRINUSE
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <errno.h>
  #define CLOSE_SOCK(s) close(s)
  #define GET_ERR       errno
  #define EADDRINUSE_VAL EADDRINUSE
  #define INVALID_SOCKET -1
  #define SOCKET_ERROR   -1
  typedef int SOCKET;
#endif

#include <string.h>
#include <stdlib.h>
#include <time.h>

static int
_set_sock_opts(SOCKET fd)
{
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                   (const char *)&one, sizeof(one)) == SOCKET_ERROR)
        return -1;
#ifdef TCP_NODELAY
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                   (const char *)&one, sizeof(one)) == SOCKET_ERROR)
        return -1;
#endif
    return 0;
}

static int
_bind_port(SOCKET fd, int src_port)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port        = htons((unsigned short)src_port);
    return bind(fd, (struct sockaddr *)&sa, sizeof(sa));
}

static int
_connect_host(SOCKET fd, const char *host, int port, double timeout_sec)
{
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[16];
    int  rc = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return -1;

#ifdef _WIN32
    DWORD tv_ms = (DWORD)(timeout_sec * 1000);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_ms, sizeof(tv_ms));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv_ms, sizeof(tv_ms));
#else
    struct timeval tv;
    tv.tv_sec  = (time_t)timeout_sec;
    tv.tv_usec = (suseconds_t)((timeout_sec - tv.tv_sec) * 1e6);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (connect(fd, rp->ai_addr, (socklen_t)rp->ai_addrlen) == 0) {
            rc = 0;
            break;
        }
    }
    freeaddrinfo(res);
    return rc;
}


/*  sport_connect(host, port, src_port, timeout) -> socket.fileno()   */


static PyObject *
sport_connect(PyObject *self, PyObject *args)
{
    const char *host;
    int         dst_port;
    int         src_port  = 0;
    double      timeout   = 15.0;
    int         max_tries = 5;

    if (!PyArg_ParseTuple(args, "si|idi",
                          &host, &dst_port, &src_port, &timeout, &max_tries))
        return NULL;

#ifdef _WIN32
    /* Winsock init — idempotent */
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);
#endif

    SOCKET  fd;
    int     attempt    = 0;
    int     cur_port   = src_port;
    int     last_errno = 0;

    while (attempt < max_tries) {
        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd == INVALID_SOCKET) {
            PyErr_SetString(PyExc_OSError, "socket() failed");
            return NULL;
        }

        if (_set_sock_opts(fd) != 0) {
            CLOSE_SOCK(fd);
            PyErr_SetString(PyExc_OSError, "setsockopt() failed");
            return NULL;
        }
        
        /* Bind source port */
        if (cur_port > 0 && _bind_port(fd, cur_port) == SOCKET_ERROR) {
            last_errno = GET_ERR;
            CLOSE_SOCK(fd);
            if (last_errno == EADDRINUSE_VAL) {
                cur_port = 32768 + (rand() % 28231);
                attempt++;
                continue;
            }
            PyErr_SetFromErrno(PyExc_OSError);
            return NULL;
        }

        if (_connect_host(fd, host, dst_port, timeout) == 0) {
            return PyLong_FromLong((long)fd);
        }

        last_errno = GET_ERR;
        CLOSE_SOCK(fd);

        if (last_errno != EADDRINUSE_VAL)
            break;

        cur_port = 32768 + (rand() % 28231);
        attempt++;
    }

    PyErr_Format(PyExc_ConnectionError,
                 "sport_connect: failed after %d attempts (errno=%d)",
                 attempt, last_errno);
    return NULL;
}


/*  sport_probe(host, port, src_port, timeout) -> status_code (int)   */


static PyObject *
sport_probe(PyObject *self, PyObject *args)
{
    const char *host;
    const char *domain;   /* host header */
    int         dst_port;
    int         src_port  = 0;
    double      timeout   = 5.0;

    if (!PyArg_ParseTuple(args, "ssi|id",
                          &host, &domain, &dst_port, &src_port, &timeout))
        return NULL;

#ifdef _WIN32
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);
#endif

    SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) {
        PyErr_SetString(PyExc_OSError, "socket() failed");
        return NULL;
    }

    _set_sock_opts(fd);

    if (src_port > 0)
        _bind_port(fd, src_port);

    if (_connect_host(fd, host, dst_port, timeout) != 0) {
        CLOSE_SOCK(fd);
        Py_RETURN_NONE;
    }

    char req_buf[1024];
    int  req_len = snprintf(
        req_buf, sizeof(req_buf),
        "HEAD / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Connection: close\r\n\r\n",
        domain
    );

    if (send(fd, req_buf, req_len, 0) == SOCKET_ERROR) {
        CLOSE_SOCK(fd);
        Py_RETURN_NONE;
    }

    char  resp_buf[256];
    int   received = 0;
    int   n;

    memset(resp_buf, 0, sizeof(resp_buf));

    while (received < (int)sizeof(resp_buf) - 1) {
        n = recv(fd, resp_buf + received,
                 (int)sizeof(resp_buf) - 1 - received, 0);
        if (n <= 0)
            break;
        received += n;
        if (memchr(resp_buf, '\n', received))
            break;
    }

    CLOSE_SOCK(fd);

    if (received < 12) {
        Py_RETURN_NONE;
    }

    int  status = 0;
    char ver[10];
    if (sscanf(resp_buf, "%9s %d", ver, &status) == 2 && status > 0)
        return PyLong_FromLong((long)status);

    Py_RETURN_NONE;
}

static PyObject *
sport_batch_probe(PyObject *self, PyObject *args)
{
    PyObject   *targets_list;
    const char *domain;
    int         src_port = 0;
    double      timeout  = 3.0;

    if (!PyArg_ParseTuple(args, "Os|id",
                          &targets_list, &domain, &src_port, &timeout))
        return NULL;

    if (!PyList_Check(targets_list)) {
        PyErr_SetString(PyExc_TypeError, "targets must be a list");
        return NULL;
    }

    Py_ssize_t n      = PyList_Size(targets_list);
    PyObject  *result = PyList_New(n);
    if (!result)
        return NULL;

    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *item = PyList_GetItem(targets_list, i);
        if (!PyTuple_Check(item) || PyTuple_Size(item) != 2) {
            PyList_SetItem(result, i, Py_BuildValue("(OOO)",
                           PyTuple_GetItem(item, 0),
                           PyTuple_GetItem(item, 1),
                           Py_None));
            continue;
        }

        const char *host = PyUnicode_AsUTF8(PyTuple_GetItem(item, 0));
        int         port = (int)PyLong_AsLong(PyTuple_GetItem(item, 1));

        if (!host || port <= 0) {
            Py_INCREF(Py_None);
            PyList_SetItem(result, i, Py_None);
            continue;
        }

#ifdef _WIN32
        WSADATA wsd;
        WSAStartup(MAKEWORD(2, 2), &wsd);
#endif
        SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        int    status_code = -1;

        if (fd != INVALID_SOCKET) {
            _set_sock_opts(fd);
            if (src_port > 0)
                _bind_port(fd, src_port);

            if (_connect_host(fd, host, port, timeout) == 0) {
                char req_buf[512];
                int  rlen = snprintf(req_buf, sizeof(req_buf),
                    "HEAD / HTTP/1.1\r\nHost: %s\r\n"
                    "User-Agent: Mozilla/5.0\r\n"
                    "Connection: close\r\n\r\n", domain);
                send(fd, req_buf, rlen, 0);

                char resp[128];
                int  rx = 0, k;
                memset(resp, 0, sizeof(resp));
                while (rx < (int)sizeof(resp) - 1) {
                    k = recv(fd, resp + rx,
                             (int)sizeof(resp) - 1 - rx, 0);
                    if (k <= 0) break;
                    rx += k;
                    if (memchr(resp, '\n', rx)) break;
                }
                char ver[10];
                sscanf(resp, "%9s %d", ver, &status_code);
            }
            CLOSE_SOCK(fd);
        }

        if (status_code > 0) {
            PyList_SetItem(result, i,
                Py_BuildValue("(sii)", host, port, status_code));
        } else {
            PyList_SetItem(result, i,
                Py_BuildValue("(siO)", host, port, Py_None));
        }
    }

    return result;
}

static PyMethodDef SportMethods[] = {
    {
        "connect",
        sport_connect,
        METH_VARARGS,
        "connect(host, port, src_port=0, timeout=15.0, max_tries=5) -> fd\n"
        "create chosen TCP and source port.\n"
        "return  file descriptor then close socket.fromfd().",
    },
    {
        "probe",
        sport_probe,
        METH_VARARGS,
        "probe(host, domain, port, src_port=0, timeout=5.0) -> status_code|None\n"
        "send  HTTP HEAD request and receive status code.",
    },
    {
        "batch_probe",
        sport_batch_probe,
        METH_VARARGS,
        "batch_probe(targets, domain, src_port=0, timeout=3.0) -> list\n"
        "targets = [(host, port), ...]\n"
        "return  [(host, port, status_code), ...] — C-speed verification.",
    },
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef sportmodule = {
    PyModuleDef_HEAD_INIT,
    "_sport_fast",
    "Fast source port manipulation — C extension for EvilWAF",
    -1,
    SportMethods,
};

PyMODINIT_FUNC
PyInit__sport_fast(void)
{
    srand((unsigned int)time(NULL));
    return PyModule_Create(&sportmodule);
}