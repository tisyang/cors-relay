#ifndef PROXY_CLUSTER_H
#define PROXY_CLUSTER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ntrip_proxy;

// read from ntripproxy, nonblocking
int ntripproxy_read(struct ntrip_proxy *proxy, void *buf, size_t size);
// write to ntripproxy, nonblocking
int ntripproxy_write(struct ntrip_proxy *proxy, const void *data, size_t size);
// get path of ntripproxy, return str is bound to proxy, DO NOT free it or modity it
const char * ntripproxy_get_path(struct ntrip_proxy *proxy);

// init proxycluster module, return 0 means OK, -1 means error
int proxycluster_init();
// get total proxy's count
int proxycluster_capacity_count();
// get using proxy's count
int proxycluster_using_count();
// try to take an proxy with port and mnt, NULL mean cannot get one
struct ntrip_proxy * proxycluster_take_proxy(int port, const char *mnt);
// free usage of the proxy
void proxycluster_release_proxy(struct ntrip_proxy *proxy);
// cleanup proxycluster module
void proxycluster_cleanup();

#ifdef __cplusplus
}
#endif

#endif // PROXY_CLUSTER_H
