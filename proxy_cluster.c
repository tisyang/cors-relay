#include "proxy_cluster.h"
#include "ulog/ulog.h"
#include "queue/queue.h"
#include "tokens.h"
#include "wsocket/utils/ntripcli.h"

#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

struct ntrip_proxy {
    char token[64]; // token: user:passwd@ipaddress
    struct ntripcli str;
    bool open;      // if str is open
    TAILQ_ENTRY(ntrip_proxy) entries;
};

// proxy list head
static TAILQ_HEAD(, ntrip_proxy) m_proxy_head = TAILQ_HEAD_INITIALIZER(m_proxy_head);

int ntripproxy_read(struct ntrip_proxy *proxy, void *buf, size_t size)
{
    if (!proxy->open) {
        return -1;
    }
    return ntripcli_read(&proxy->str, buf, size);
}

int ntripproxy_write(struct ntrip_proxy *proxy, const void *data, size_t size)
{
    if (!proxy->open) {
        return -1;
    }
    return ntripcli_write(&proxy->str, data, size);
}

const char * ntripproxy_get_path(struct ntrip_proxy *proxy)
{
    if (!proxy->open) {
        return NULL;
    }
    return proxy->str.path_cache;
}

int proxycluster_init()
{
    if (TAILQ_EMPTY(&m_proxy_head)) {
        return 0;
    } else {
        LOG_ERROR("%() already init.", __func__);
        return -1;
    }
}


int proxycluster_capacity_count()
{
    return tokens_src_count();
}

int proxycluster_using_count()
{
    return tokens_src_count_used();
}

struct ntrip_proxy * proxycluster_take_proxy(int port, const char *mnt)
{
    char token[64];
    if (tokens_src_take_path(token, sizeof(token)) == NULL) {
        LOG_ERROR("cannot get usable source tokens");
        return NULL;
    }
    struct ntrip_proxy *proxy = malloc(sizeof(*proxy));
    if (proxy == NULL) {
        LOG_ERROR("malloc failed, %s", strerror(errno));
        tokens_src_release_path(token);
        return NULL;
    }
    snprintf(proxy->token, sizeof(proxy->token), token);
    ntripcli_init(&proxy->str, 5, 15, -1);
    proxy->open = false;
    char path[256];
    snprintf(path, sizeof(path), "%s:%d/%s", token, port, mnt);
    if (ntripcli_open_path(&proxy->str, path) != 0) {
        LOG_ERROR("stropen failed, path='%s'", path);
        tokens_src_release_path(token);
        return NULL;
    }
    proxy->open = true;
    TAILQ_INSERT_TAIL(&m_proxy_head, proxy, entries);
    return proxy;
}

void proxycluster_release_proxy(struct ntrip_proxy *proxy)
{
    TAILQ_REMOVE(&m_proxy_head, proxy, entries);
    tokens_src_release_path(proxy->token);
    ntripcli_close(&proxy->str);
    proxy->open = false;
    free(proxy);
}

void proxycluster_cleanup()
{
    struct ntrip_proxy *pry, *tmp;
    TAILQ_FOREACH_SAFE(pry, &m_proxy_head, entries, tmp) {
        proxycluster_release_proxy(pry);
    }
}
