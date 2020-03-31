#include "ulog/ulog.h"
#include "wsocket/wsocket.h"
#include "wsocket/utils/tcpsvr.h"
#include "queue/queue.h"
#include "base64.h"
#include "geohash.h"
#include "tokens.h"
#include "proxy_cluster.h"
#include "libfort/fort.h"
#include "repo_version.h"

#ifdef _WIN32
# include "evwrap.h"
#else
# include <ev.h>
#endif
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stddef.h>
#include <signal.h>
#include <stdbool.h>
#include <math.h>


#define DEFAULT_CONSOLE_PASSWD "passwd"
#define TOKENS_DB_FILE  "cors-relay.db"

static char * env_console_passwd()
{
    char *p = getenv("CONSOLE_PASSWD");
    return p ? p : DEFAULT_CONSOLE_PASSWD;
}

#define CONSOLE_PASSWD  env_console_passwd()

struct ntrip_caster;
struct ntrip_source;

struct ntrip_conn {
    ev_io   io;
    wsocket socket;
    int     gate;
    char    ip[64];
    ev_tstamp last_activity;
    unsigned char recv[1024];
    size_t  recv_idx;

    struct ntrip_caster *caster;
    TAILQ_ENTRY(ntrip_conn) entries; // used for connection
};

struct ntrip_agent {
    ev_io   io;
    wsocket socket;
    int     gate;
    char    ip[64];
    ev_tstamp last_activity;
    unsigned char recv[1024];
    size_t  recv_idx;

    struct ntrip_caster *caster;    // caster, weak ref

    char token[64];     // ntrip token
    char mnt[64];       // ntrip mnt
    char info[64];      // ntrip agent info
    time_t login_time;  // ntrip login time

    // recent location
    char   ggastr[256]; // recent gga string
    double pos[3];      // lat(deg),long(deg) height(m)
    double ecef[3];     // ecef coordinate

    struct ntrip_source *source; // bound ntrip_source, weak ref
    int    source_ref_idx;

    size_t in_bytes;    // in bytes
    size_t in_bps;      // in bps
    size_t out_bytes;   // out bytes
    size_t out_bps;     // out bps

    TAILQ_ENTRY(ntrip_agent) entries;       // use in caster's list
    TAILQ_ENTRY(ntrip_agent) src_entries;   // use in source's list
};

#define AGENT_HAS_GGA(agent)    (agent->ggastr[0] != '\0')
#define AGENT_HAS_POS(agent)    (agent->ecef[0] != 0.0)
#define AGENT_IS_BOUND(agent)   (agent->source != NULL)


struct ntrip_source {
    struct ntrip_proxy *proxy;
    time_t proxy_activity;
    int  gate;
    char mnt[64];
    TAILQ_HEAD(, ntrip_agent) agents_head[2];   // first and second bound agents list, weak ref,
    unsigned char agents_cache[2][512];    // cache data
    size_t        agents_cache_cnt[2];      // cache data len
    int swmagic;    // >= 0 use idx=0, < 0 use idx = 1

    struct ntrip_caster *caster;
    TAILQ_ENTRY(ntrip_source) entries;
};

struct ntrip_listener {
    ev_io   io;
    wsocket socket; // listen socket
    int     gate;   // listen port

    struct ntrip_caster *caster;
    TAILQ_ENTRY(ntrip_listener) entries;
};

struct ntrip_caster {
    ev_timer timer_check; // timer for check agent alive
    ev_timer timer_src;   // timer for sending source gga
    ev_timer timer_log;   // timer for loging status
    ev_stat  stat_user;   // stat watcher for user tokens file change
    ev_stat  stat_src;    // stat watcher for source tokens file change
    ev_periodic periodic_reload; // periodic to reload user tokens file

    TAILQ_HEAD(, ntrip_listener) listeners_head; // listener list, owned
    TAILQ_HEAD(, ntrip_conn)     conn_head;      // connections list(not login), owned
    TAILQ_HEAD(, ntrip_agent)    agents_head;    // active agents list, owned
    TAILQ_HEAD(, ntrip_source)   sources_head;   // source list, owned

    ev_io   cmd_io;
    wsocket cmd_sock;

    struct tcpsvr *log;
};

#define NTRIP_RESPONSE_OK           "ICY 200 OK\r\n"
#define NTRIP_RESPONSE_UNAUTHORIZED "HTTP/1.0 401 Unauthorized\r\n"
#define NTRIP_RESPONSE_FORBIDDEN    "HTTP/1.0 403 Forbidden\r\n"
#define NTRIP_RESPONSE_ERROR_PASSED "ERROR - Bad Password\r\n"
#define NTRIP_RESPONSE_ERROR_MOUNTP "ERROR - Bad Mountpoint\r\n"

#define SEND(s, str)    send(s, str, strlen(str), 0)

static wsocket listen_on(const char *addr, const char* service)
{
    wsocket sock = INVALID_WSOCKET;

    struct addrinfo hints = {0};
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int rv = 0;
    struct addrinfo *ai = NULL;
    if ((rv = getaddrinfo(addr, service, &hints, &ai)) != 0) {
        LOG_ERROR("getaddrinfo() error, %s", gai_strerror(rv));
        return INVALID_WSOCKET;
    }
    for (const struct addrinfo *p = ai; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (wsocket_set_nonblocking(sock) == WSOCKET_ERROR) {
            LOG_ERROR("set nonblocking error, %s", wsocket_strerror(wsocket_errno));
            wsocket_close(sock);
            return INVALID_WSOCKET;
        }
        if (sock == INVALID_WSOCKET) {
            continue;
        }
        // enable addr resuse
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&(int){1}, sizeof(int));
        if (bind(sock, p->ai_addr, p->ai_addrlen) == WSOCKET_ERROR) {
            // bind error
            wsocket_close(sock);
            sock = INVALID_WSOCKET;
            continue;
        }
        // Got it!
        break;
    }

    if (sock == INVALID_WSOCKET) {
        LOG_ERROR("socket() or bind() error, %s", wsocket_strerror(wsocket_errno));
        freeaddrinfo(ai);
        ai = NULL;
        return INVALID_WSOCKET;
    }

    freeaddrinfo(ai);
    ai = NULL;

    if (listen(sock, 2) == WSOCKET_ERROR) {
        LOG_ERROR("listen() error, %s", wsocket_strerror(wsocket_errno));
        wsocket_close(sock);
        return INVALID_WSOCKET;
    }

    return sock;
}

/* convert ddmm.mm in nmea format to deg -------------------------------------*/
static double dmm2deg(double dmm)
{
    return floor(dmm/100.0)+fmod(dmm,100.0)/60.0;
}

static void pos2ecef(const double *pos, double *r)
{
#define RE_WGS84    6378137.0           /* earth semimajor axis (WGS84) (m) */
#define FE_WGS84    (1.0/298.257223563) /* earth flattening (WGS84) */

    double sinp=sin(pos[0]),cosp=cos(pos[0]),sinl=sin(pos[1]),cosl=cos(pos[1]);
    double e2=FE_WGS84*(2.0-FE_WGS84),v=RE_WGS84/sqrt(1.0-e2*sinp*sinp);

    r[0]=(v+pos[2])*cosp*cosl;
    r[1]=(v+pos[2])*cosp*sinl;
    r[2]=(v*(1.0-e2)+pos[2])*sinp;
}

static bool agent_calc_location(struct ntrip_agent *agent)
{
#define D2R (M_PI/180.0)
    if (AGENT_HAS_GGA(agent)) {
        // parse gga fileds
        char gga[128];
        snprintf(gga, sizeof(gga), agent->ggastr);
        char *val[64];
        int n = 0;
        char *p, *q;
        for (p = gga; *p && n < sizeof(val)/sizeof(val[0]); p = q + 1) {
            if ((q = strchr(p, ',')) || (q = strchr(p, '*'))) {
                val[n++] = p;
                *q = '\0';
            } else {
                break;
            }
        }
        // $xxGGA
        if (n >= 13 && strlen(val[0]) > 4 && strcmp(val[0] + 3, "GGA") == 0) {
            double lat = 0.0, lon = 0.0, alt = 0.0, msl = 0.0;
            char ns = 'N', ew = 'E';
            lat = atof(val[2]);  /* latitude (ddmm.mmm) */
            ns  = *val[3];       /* N=north,S=south */
            lon = atof(val[4]);  /* longitude (dddmm.mmm) */
            ew  = *val[5];       /* E=east,W=west */
            alt =atof(val[9]);   /* altitude in msl */
            msl =atof(val[11]);  /* height of geoid */
            if ((ns != 'N' && ns != 'S') || (ew != 'E' && ew != 'W')) {
                LOG_ERROR("invalid nmea gpgga format");
                return false;
            }
            if (lat == 0.0) {
                LOG_ERROR("empty nmea gpgga");
                return false;
            }
            agent->pos[0] = (ns == 'N' ? 1.0 : -1.0) * dmm2deg(lat);
            agent->pos[1] = (ew == 'E' ? 1.0 : -1.0) * dmm2deg(lon);
            agent->pos[2] = alt + msl;
            // calc ecef
            double pos[3] = {0};
            pos[0] = agent->pos[0] * D2R;
            pos[1] = agent->pos[1] * D2R;
            pos[2] = agent->pos[2];
            pos2ecef(pos, agent->ecef);
            return true;
        }
    }
    return false;
}

static double agent_distance(const struct ntrip_agent *ag1, const struct ntrip_agent *ag0)
{
    double dd[3];
    for (int i = 0; i < 3; i++) {
        dd[i] = ag1->ecef[i] - ag0->ecef[i];
    }
    return sqrt(dd[0] * dd[0] + dd[1] * dd[1] + dd[2] * dd[2]);
}
static bool caster_bind_agent(struct ntrip_caster *caster, struct ntrip_agent *agent)
{
    if (AGENT_IS_BOUND(agent)) {
        LOG_ERROR("%s() is already bound", __func__);
        return false;
    }
    if (!AGENT_HAS_POS(agent)) {
        LOG_ERROR("%s() expect agent with position", __func__);
        return false;
    }

    struct ntrip_source *match = NULL, *wedge = NULL;
    int match_idx = 0, wedge_idx = 0;
    // search if a source that gate and mnt is same, and distance is short (< 30km)
    struct ntrip_source *src;
    TAILQ_FOREACH(src, &caster->sources_head, entries) {
        if (src->gate == agent->gate && strcasecmp(src->mnt, agent->mnt) == 0) {
            for (int i = 0; i < 2; i++) {
                struct ntrip_agent* srcag = TAILQ_FIRST(&src->agents_head[i]);
                // find first wedge
                if (srcag == NULL && wedge == NULL) {
                    wedge = src;
                    wedge_idx = i;
                }
                // gate and mnt must be same, and then calcute distance
                if (srcag) {
                    double d = agent_distance(agent, srcag);
                    if (d < 30000) { // less than 30 km
                        match = src;
                        match_idx = i;
                    }
                }
            }
        }
    }
    if (match == NULL) { // no match source
        // first, try create new source
        struct ntrip_proxy *proxy = proxycluster_take_proxy(agent->gate, agent->mnt);
        if (proxy != NULL) {
            struct ntrip_source *source = malloc(sizeof(*source));
            if (source == NULL) {
                LOG_ERROR("malloc error, %s", strerror(errno));
                proxycluster_release_proxy(proxy);
            } else {
                source->proxy = proxy;
                source->proxy_activity = time(NULL);
                source->gate = agent->gate;
                snprintf(source->mnt, sizeof(source->mnt), agent->mnt);
                TAILQ_INIT(&source->agents_head[0]);
                TAILQ_INIT(&source->agents_head[1]);
                source->agents_cache_cnt[0] = 0;
                source->agents_cache_cnt[1] = 0;
                source->swmagic = 0;
                source->caster = caster;
                // insert to caster->source_head
                TAILQ_INSERT_TAIL(&caster->sources_head, source, entries);
                match = source;
                match_idx = 0;
                LOG_TRACE("create source(%s) for agent(%d)", ntripproxy_get_path(source->proxy), agent->socket);
            }
        } else {
            LOG_INFO("all proxy is in use, no more new proxy");
        }
    }
    if (match == NULL) { // no more new source
        // try to use wedge
        if (wedge == NULL) {
            LOG_ERROR("no more usable source, wedge is FULL");
        } else {
            match = wedge;
            match_idx = wedge_idx;
        }
    }
    // final check
    if (match == NULL) {
        LOG_ERROR("cannot bind valid source to agent(%d)", agent->socket);
        return false;
    } else {
        LOG_TRACE("bind source(%s) with agent(%d)", ntripproxy_get_path(match->proxy), agent->socket);
        // add weak ref to each other
        TAILQ_INSERT_TAIL(&match->agents_head[match_idx], agent, src_entries);
        agent->source = match;
        agent->source_ref_idx = match_idx;
        return true;
    }
}

static void caster_relax_agent(struct ntrip_caster *caster, struct ntrip_agent *agent)
{
    if (!AGENT_IS_BOUND(agent)) {
        LOG_ERROR("%s() is not bound", __func__);
        return;
    }
    struct ntrip_source *source = agent->source;
    LOG_TRACE("detach agent(%d) with source(%s)", agent->socket, ntripproxy_get_path(source->proxy));
    // remove weak ref to each other
    TAILQ_REMOVE(&source->agents_head[agent->source_ref_idx], agent, src_entries);
    // check if source no-need-work
    if (TAILQ_EMPTY(&source->agents_head[0]) &&  TAILQ_EMPTY(&source->agents_head[1])) {
        // remove it from caster and close it
        LOG_TRACE("close source(%s)", ntripproxy_get_path(source->proxy));
        TAILQ_REMOVE(&caster->sources_head, source, entries);
        proxycluster_release_proxy(source->proxy);
        free(source);
    }
    agent->source = NULL;
    agent->source_ref_idx = 0;
}

// only cleanup conn resource
static void close_conn(EV_P_ struct ntrip_conn *conn)
{
    LOG_INFO("close conn(%d) from %s", conn->socket, conn->ip);
    ev_io_stop(EV_A_ &conn->io);
    wsocket_close(conn->socket);
    free(conn);
}
// only cleanup agent and conn resource
static void close_agent(EV_P_ struct ntrip_agent *agent)
{
    LOG_INFO("close agent(%d) from %s", agent->socket, agent->ip);
    ev_io_stop(EV_A_ &agent->io);
    wsocket_close(agent->socket);
    free(agent);
}

static void caster_close_conn(EV_P_ struct ntrip_caster *caster, struct ntrip_conn *conn)
{
    LOG_INFO("remove conn(%d) from connections list", conn->socket);
    TAILQ_REMOVE(&caster->conn_head, conn, entries);
    close_conn(EV_A_ conn);
}

static void caster_close_agent(EV_P_ struct ntrip_caster *caster, struct ntrip_agent *agent)
{
    if (AGENT_IS_BOUND(agent)) {
        caster_relax_agent(caster, agent);
    }
    LOG_INFO("remove agent(%d) from agents list", agent->socket);
    TAILQ_REMOVE(&caster->agents_head, agent, entries);
    close_agent(EV_A_ agent);
}

// check if caster has  the mountpoint source
static int caster_has_mountpoint(const struct ntrip_caster *caster, const char* mnt)
{
    // invalid mnt
    if (mnt[0] == '\0' || strcmp(mnt, "/") == 0) {
        return 0;
    }
    if (strcasecmp(mnt, "RTCM30_GG") == 0 ||
        strcasecmp(mnt, "RTCM23_GPS") == 0 ||
        strcasecmp(mnt, "RTCM32_GGB") == 0) {
        return 1;
    }
    return 0;
}

static const char* caster_gen_sourcetable(const struct ntrip_caster *caster)
{
    const char * _srctbbuf = ""
        "STR;RTCM30_GG;RTCM30_GG;RTCM3X;1005(10),1004-1012(1),1033(10);2;GNSS;POPNet;CHN;0.00;0.00;1;1;POP Platform;none;B;N;500;POP\r\n"
        "STR;RTCM23_GPS;RTCM23_GPS;RTCM2X;1(1),31(1),41(1),3(10),32(30);2;GNSS;POPNet;CHN;0.00;0.00;1;1;POP Platform;none;B;N;500;POP\r\n"
        "STR;RTCM32_GGB;RTCM32_GGB;RTCM3X;1005(10),1074-1084-1124(1);2;GNSS;POPNet;CHN;0.00;0.00;1;1;POP Platform;none;B;N;500;POP\r\n"
        "ENDSOURCETABLE\r\n";
    return _srctbbuf;
}

static bool caster_match_client_token(const struct ntrip_caster *caster, const char* token, const char* mnt)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", token);
    char *p = strchr(buf, ':');
    if (p) {
        *p = '\0';
        return tokens_user_permit(buf, p + 1);
    }
    return false;
}

static struct ntrip_agent* caster_check_login(const struct ntrip_caster *caster, const char *token)
{
    struct ntrip_agent* ag;
    TAILQ_FOREACH(ag, &caster->agents_head, entries) {
        if (strcmp(ag->token, token) == 0) {
            return ag;
        }
    }
    return NULL;
}

static void agent_read_cb(EV_P_ ev_io *w, int revents)
{
    struct ntrip_agent *agent = (struct ntrip_agent *)w;
    struct ntrip_caster *caster = agent->caster;

    int n = recv(agent->socket,
                 agent->recv + agent->recv_idx,
                 sizeof(agent->recv) - agent->recv_idx - 1,
                 0);
    if (n == WSOCKET_ERROR && wsocket_errno != WSOCKET_EWOULDBLOCK) {
        LOG_INFO("agent(%d) recv error, %s", agent->socket, wsocket_strerror(wsocket_errno));
        caster_close_agent(EV_A_ caster, agent);
        return;
    }
    if (n == 0) {
        LOG_INFO("agent(%d) connection close", agent->socket);
        caster_close_agent(EV_A_ caster, agent);
        return;
    }
    if (n < 0) { // maybe -1 since WSOCKET_EWOULDBLOCK
        return;
    }
    agent->recv_idx += n;
    agent->in_bytes += n;
    agent->in_bps = n * 8;
    // check pending buffer overflow
    if (agent->recv_idx >= sizeof(agent->recv) - 1) {
        LOG_ERROR("agent(%d) recv buffer overflow", agent->socket);
        caster_close_agent(EV_A_ caster, agent);
        return;
    }
    agent->recv[agent->recv_idx] = '\0';
    // search for gga
    char *p = strchr(agent->recv, '$');
    char *g = NULL;
    if (p && strlen(p) > 6 && strncmp(p + 3, "GGA", 3) == 0) {
        char *q = strstr(p, "\r\n");
        if (q) { // found
            *q = '\0';
            agent->recv_idx = 0;
            snprintf(agent->ggastr, sizeof(agent->ggastr), "%s\r\n", p);
            if (!agent_calc_location(agent)) {
                LOG_ERROR("agent(%d) calc loaction error", agent->socket);
            } else {
                //LOG_DEBUG("agent(%d) loc: %f %f %f", agent->socket, agent->pos[0], agent->pos[1], agent->pos[2]);
                agent->last_activity = ev_now(EV_A);
            }
            // bound agent
            if (!AGENT_IS_BOUND(agent)) {
                if (!caster_bind_agent(caster, agent)) {
                    LOG_WARN("agent(%d) bind to source error, let it un-bound", agent->socket);
                }
            }
        }
    }
}

static void conn_read_cb(EV_P_ ev_io *w, int revents)
{
    struct ntrip_conn *conn = (struct ntrip_conn *)w;
    struct ntrip_caster *caster = conn->caster;

    int n = recv(conn->socket,
                 conn->recv + conn->recv_idx,
                 sizeof(conn->recv) - conn->recv_idx - 1,
                 0);
    if (n == WSOCKET_ERROR && wsocket_errno != WSOCKET_EWOULDBLOCK) {
        LOG_INFO("conn(%d) recv error, %s", conn->socket, wsocket_strerror(wsocket_errno));
        caster_close_conn(EV_A_ caster, conn);
        return;
    }
    if (n == 0) {
        LOG_INFO("conn(%d) connection close", conn->socket);
        caster_close_conn(EV_A_ caster, conn);
        return;
    }
    if (n < 0) { // maybe -1 since WSOCKET_EWOULDBLOCK
        return;
    }
    conn->last_activity = ev_now(EV_A);
    conn->recv_idx += n;
    // check pending buffer overflow
    if (conn->recv_idx >= sizeof(conn->recv) - 1) {
        LOG_ERROR("conn(%d) recv buffer overflow", conn->socket);
        caster_close_conn(EV_A_ caster, conn);
        return;
    }
    conn->recv[conn->recv_idx] = '\0';
    // check ntrip request, end with \r\n\r\n
    if (strstr(conn->recv, "\r\n\r\n")) {
        char *p = strstr(conn->recv, "GET");
        if (p == NULL) {
            LOG_ERROR("conn(%d) invalid ntrip request", conn->socket);
            caster_close_conn(EV_A_ caster, conn);
            return;
        }
        // process ntrip client requst
        // TODO:
        char *q, *ag;
        if (!(q = strstr(p, "\r\n")) || !(ag = strstr(q, "User-Agent:")) || !strstr(ag, "\r\n")) {
            LOG_ERROR("conn(%d) invalid ntrip request", conn->socket);
            caster_close_conn(EV_A_ caster, conn);
            return;
        }
        ag += strlen("User-Agent:");
        char useragent[64];
        // fill user agent
        sscanf(ag, "%63[^\n]", useragent);
        // test protocol
        char url[64] = {0};
        char proto[64] = {0};
        if (sscanf(p, "GET %s %s", url, proto) < 2 || strncmp(proto, "HTTP/1", strlen("HTTP/1")) != 0) {
            LOG_ERROR("conn(%d) invalid ntrip proto=%s", conn->socket, proto);
            caster_close_conn(EV_A_ caster, conn);
            return;
        }
        char mnt[64];
        snprintf(mnt, sizeof(mnt), "%s", url[0] == '/' ? url + 1 : url);
        // check if mountpoint exist, if not , send source table
        if (!caster_has_mountpoint(caster, mnt)) {
            // send source table
            LOG_DEBUG("send source table to conn(%d) from %s",
                      conn->socket, conn->ip);
            const char* srctb = caster_gen_sourcetable(caster);
            int srctblen = strlen(srctb);
            char buf[256];
            buf[0] = '\0';
            time_t now = time(NULL);
            // NOTE: DO NOT use time functions in LOG_XXX macros
            char* timestr = strdup(asctime(gmtime(&now)));
            snprintf(buf, sizeof(buf),
                "SOURCETABLE 200 OK\r\n"
                "Server: https://github.com/tisyang/cors-relay\r\n"
                "Date: %.24s UTC\r\n"
                "Connection: close\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %d\r\n\r\n",
                timestr, srctblen);
            free(timestr);
            if (send(conn->socket, buf, strlen(buf), 0) > 0) {
                send(conn->socket, srctb, srctblen, 0);
            }
            caster_close_conn(EV_A_ caster, conn);
            return;
        }
        // check authentication
        int auth = 0; // if authorization success
        char token[64];
        if ((p = strstr(conn->recv, "Authorization:"))) {
            char method[32] = {0};
            char tokenbuf[64] = {0};
            if (sscanf(p, "Authorization: %s %s", method, tokenbuf) == 2) {
                if (strcmp(method, "Basic") == 0) {
                    // decode token
                    size_t tklen = 0;
                    unsigned char* tk = base64_decode(tokenbuf, strlen(tokenbuf), &tklen);
                    if (tk) {
                        snprintf(token, sizeof(token), "%.*s", tklen, tk);
                        free(tk);
                        if (caster_match_client_token(caster, token, mnt)) {
                            auth = 1;
                        }
                    }
                }
            }
        }
        if (!auth) { // auth failed
            LOG_INFO("agent(%d) client authorization failed.", conn->socket);
            send(conn->socket, NTRIP_RESPONSE_UNAUTHORIZED,
                strlen(NTRIP_RESPONSE_UNAUTHORIZED), 0);
            caster_close_conn(EV_A_ caster, conn);
            return;
        }
        // check if already login
        struct ntrip_agent* oldag = caster_check_login(caster, token);
        if (oldag) {
            // close old ones
            LOG_INFO("close already login agent(%d)", oldag->socket);
            caster_close_agent(EV_A_ caster, oldag);
        }
        // create pending agent
        struct ntrip_agent *agent = malloc(sizeof(*agent));
        if (agent == NULL) {
            LOG_ERROR("malloc error, %s", strerror(errno));
            caster_close_conn(EV_A_ caster, conn);
            return;
        }
        // copy from conn to agent
        agent->socket = conn->socket;
        snprintf(agent->ip, sizeof(agent->ip), conn->ip);
        agent->gate = conn->gate;
        agent->last_activity = conn->last_activity;
        agent->recv[0] = '\0';
        agent->recv_idx = 0;
        ev_io_stop(EV_A_ &conn->io);
        LOG_INFO("remove conn(%d) from connections list", conn->socket);
        TAILQ_REMOVE(&caster->conn_head, conn, entries);
        free(conn);

        // use agent read cb
        ev_io_init(EV_A_ &agent->io, agent_read_cb, WSOCKET_GET_FD(agent->socket), EV_READ);
        ev_io_start(EV_A_ &agent->io);
        snprintf(agent->token, sizeof(agent->token), token);
        snprintf(agent->mnt, sizeof(agent->mnt), mnt);
        snprintf(agent->info, sizeof(agent->info), useragent);
        agent->login_time = time(NULL);
        agent->ggastr[0] = '\0';
        for (int i = 0; i < 3; i++) {
            agent->pos[i] = 0;
            agent->ecef[i] = 0;
        }
        agent->source = NULL;
        agent->source_ref_idx = 0;
        agent->in_bytes = 0;
        agent->in_bps = 0;
        agent->out_bytes = 0;
        agent->out_bps = 0;
        agent->caster = caster;
        // send response
        SEND(conn->socket, NTRIP_RESPONSE_OK);
        LOG_INFO("move agent(%d) into client agents", agent->socket);
        TAILQ_INSERT_TAIL(&caster->agents_head, agent, entries);
    }
}

static void listener_accept_cb(EV_P_ ev_io *w, int revents)
{
    struct ntrip_listener *listener = (struct ntrip_listener *)w;
    struct ntrip_caster *caster = listener->caster;

    wsocket sock = INVALID_WSOCKET;
    struct sockaddr_storage conn_addr = {0};
    socklen_t conn_addrlen = sizeof(conn_addr);

    if (EV_ERROR & revents) {
        LOG_ERROR("invalid ev event with error");
        return;
    }

    sock = accept(listener->socket, (struct sockaddr *)&conn_addr, &conn_addrlen);
    if (sock == INVALID_WSOCKET) {
        LOG_ERROR("accept() error, %s", wsocket_strerror(wsocket_errno));
        return;
    }
    // set nonblocking
    wsocket_set_nonblocking(sock);
    // print connect info
    char addrbuf[NI_MAXHOST] = {0};
    char servbuf[NI_MAXSERV] = {0};
    int rv = 0;
    if ((rv = getnameinfo((struct sockaddr *)&conn_addr, conn_addrlen,
                          addrbuf, sizeof(addrbuf),
                          servbuf, sizeof(servbuf),
                          NI_NUMERICHOST | NI_NUMERICSERV)) == 0) {
        LOG_INFO("accept conn(%d) from %s:%s", sock, addrbuf, servbuf);

    } else {
        LOG_ERROR("getnameinfo() error, %s", gai_strerror(rv));
    }

    struct ntrip_conn *conn = malloc(sizeof(*conn));
    if (conn == NULL) {
        LOG_ERROR("malloc() error, %s", strerror(errno));
        wsocket_close(sock);
        return;
    }
    conn->socket = sock;
    conn->gate = listener->gate;
    snprintf(conn->ip, sizeof(conn->ip), addrbuf);
    conn->last_activity = ev_now(EV_A);
    conn->recv[0] = '\0';
    conn->recv_idx = 0;
    conn->caster = caster;

    ev_io_init(&conn->io, conn_read_cb, WSOCKET_GET_FD(conn->socket), EV_READ);
    ev_io_start(EV_A_  &conn->io);
    LOG_INFO("move conn(%d) to connections list", conn->socket);
    TAILQ_INSERT_TAIL(&caster->conn_head, conn, entries);
}

static void caster_tmcheck_cb(EV_P_ ev_timer *w, int revents)
{
    struct ntrip_caster *caster = (struct ntrip_caster *)((char *)w - offsetof(struct ntrip_caster, timer_check));
    ev_tstamp now = ev_now(EV_A);
    // check conn list
    struct ntrip_conn *conn, *tmpconn;
    TAILQ_FOREACH_SAFE(conn, &caster->conn_head, entries, tmpconn) {
        if (now - conn->last_activity >= 60.0) {
            LOG_INFO("timeout conn(%d) from %s", conn->socket, conn->ip);
            caster_close_conn(EV_A_ caster, conn);
        }
    }
    // check agent list
    struct ntrip_agent *agent, *tmpagent;
    TAILQ_FOREACH_SAFE(agent, &caster->agents_head, entries, tmpagent) {
        if (now - agent->last_activity >= 60.0) {
            LOG_INFO("timeout agent(%d) from %s", agent->socket, agent->ip);
            caster_close_agent(EV_A_ caster, agent);
        }
    }
}

static void caster_tmsrc_cb(EV_P_ ev_timer *w, int revents)
{
    time_t now = time(NULL);
    struct ntrip_caster *caster = (struct ntrip_caster *)((char *)w - offsetof(struct ntrip_caster, timer_src));
    struct ntrip_source *src, *tmpsrc;
    TAILQ_FOREACH_SAFE(src, &caster->sources_head, entries, tmpsrc) {
        struct ntrip_agent *ag0 = TAILQ_FIRST(&src->agents_head[0]);
        struct ntrip_agent *ag1 = TAILQ_FIRST(&src->agents_head[1]);
        struct ntrip_agent *ag = NULL;
        if (ag0 && ag1) {
            // switch using
            ag = src->swmagic >= 0 ? ag0 : ag1;
            src->swmagic += 1;
            if (src->swmagic == 5) {
                src->swmagic = -5;
            }
        } else {
            ag = ag0 ? ag0 : ag1;
        }
        if (ag) {
            // send gga
            ntripproxy_write(src->proxy, ag->ggastr, strlen(ag->ggastr));
        }
        // warning about this proxy due it is not active
        double elapsed = difftime(now, src->proxy_activity);
        if (AGENT_HAS_POS(ag) && elapsed > 30) {
            LOG_WARN("source(%s)'s last activity is %.0f seconds ago", ntripproxy_get_path(src->proxy), elapsed);
            // close agent
            caster_close_agent(EV_A_ caster, ag);
        }
    }
}

#define WRITE_STR(s, fp, psock, str) do {\
    if (fp) { \
        fprintf(fp, str); \
        if (s) tcpsvr_write(s, str, strlen(str)); \
    } \
    if (psock) send(*psock, str, strlen(str), 0); \
} while (0)

static void system_report(ev_tstamp now, struct ntrip_caster *caster,
                          FILE *fp, wsocket *psock)
{
    // print status of all activity
    WRITE_STR(caster->log, fp, psock, "==== BEGIN SYSTEM REPORT ====\n");
    WRITE_STR(caster->log, fp, psock, REPO_VERSION ", " REPO_DATE "\n");
    WRITE_STR(caster->log, fp, psock, ctime(&(time_t){time(NULL)}));
    {
        WRITE_STR(caster->log, fp, psock, "Resources Usage Table:\n");
        int user_total = tokens_user_count();
        int user_online = 0;
        struct ntrip_agent *ag;
        TAILQ_FOREACH(ag, &caster->agents_head, entries) {
            user_online += 1;
        }
        int src_total = proxycluster_capacity_count();
        int src_used = proxycluster_using_count();
        ft_table_t *table = ft_create_table();
        ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
        ft_write_ln(table, "Users\nOnline", "Users\nTotal", "Online\nRate", "Source\nUsing",
                    "Source\nTotal", "Source\nRate", "Potency");
        ft_printf_ln(table, "%d|%d|%.1f %%|%d|%d|%.1f %%|%.1f %%",
                     user_online, user_total,
                     user_total <= 0 ? 0 : (float)user_online/user_total * 100,
                     src_used, src_total,
                     src_total <= 0  ? 0 : (float)src_used/src_total * 100,
                     src_total <= 0  ? 0 : (float)user_online/src_total * 100);
        WRITE_STR(caster->log, fp, psock, ft_to_string(table));
        ft_destroy_table(table);
    }
    {
        WRITE_STR(caster->log, fp, psock, "Connections Table:\n");
        ft_table_t *table = ft_create_table();
        ft_set_border_style(table, FT_BASIC_STYLE);
        ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
        ft_write_ln(table, "Source", "Slot", "Client", "Client IP", "Location", "Login Time", "Out Bps", "Out Bytes");

        struct ntrip_source *src;
        TAILQ_FOREACH(src, &caster->sources_head, entries) {
            char path[128];
            // user:passwd@ip:port/mnt
            // shadow password in path
            {
                const char *p = ntripproxy_get_path(src->proxy);
                char *colon = strchr(p, ':');
                char *at = strrchr(p, '@');
                if (colon && at) {
                    snprintf(path, sizeof(path), "%.*s%s", colon - p, p, at);
                }
            }
            for (int i = 0; i < 2; i++) {
                int slot = i;
                struct ntrip_agent *ag;
                TAILQ_FOREACH(ag, &src->agents_head[i], src_entries) {
                    char time[32];
                    struct tm *timeinfo = localtime(&ag->login_time);
                    strftime(time, sizeof(time), "%m-%d %H:%M", timeinfo);
                    int obps = (now - ag->last_activity) < 5.0 ? ag->out_bps : 0;
                    float obytes = ag->out_bytes / 1024.0;
                    char *loc = geohash_encode(ag->pos[0], ag->pos[1], 6);
                    char user[16];
                    snprintf(user, sizeof(user), ag->token);
                    char *colon = strchr(user, ':');
                    if (colon) *colon = 0;
                    ft_printf_ln(table, "%s|%d|%s|%s|%s|%s|%d|%.1f KB", path, slot,
                                 user, ag->ip, loc, time, obps, obytes);
                    free(loc);
                }
            }
            ft_add_separator(table);
        }
        WRITE_STR(caster->log, fp, psock, ft_to_string(table));
        ft_destroy_table(table);
    }
    WRITE_STR(caster->log, fp, psock, "==== END SYSTEM REPORT ====\n");
}

static void caster_tmlog_cb(EV_P_ ev_timer *w, int revents)
{
    struct ntrip_caster *caster = (struct ntrip_caster *)((char *)w - offsetof(struct ntrip_caster, timer_log));
    ev_tstamp now = ev_now(EV_A);
    system_report(now, caster, stdout, NULL);
}

static void caster_midnight_cb(EV_P_ ev_periodic *w, int revents)
{
    LOG_INFO("midnight comming, now run tokens user gc");
    tokens_user_gc();
}

#define NTRIP_CMD_RESPONSE_BAD_COMMAND  "ERROR bad command\r\n"
#define NTRIP_CMD_RESPONSE_BAD_PASSWD   "ERROR bad password\r\n"

struct ntrip_cmd_arg {
    wsocket socket;
    struct ntrip_caster *caster;
};

static void on_iter_usertokens(void *userdata, const char *user, const char *passwd, const char *expire)
{
    wsocket sock = (wsocket)userdata;
    char out[128];
    out[0] = '\0';
    snprintf(out, sizeof(out), "%s:%s\t%s\r\n", user, passwd, expire);
    SEND(sock, out);
}

static void on_iter_srctokens(void *userdata, const char* token, const char *expire)
{
    wsocket sock = (wsocket)userdata;
    char path[64];
    snprintf(path, sizeof(path), "%s", token);
    char *p = strchr(path, '@');
    if (p) {
        *p = '\0';
    } else {
        LOG_WARN("invalid source token '%s' in db", token);
        return;
    }
    char out[256];
    out[0] = '\0';
    snprintf(out, sizeof(out), "%s\t%s\t%s\t?\r\n", p + 1, path, expire);
    SEND(sock, out);
}

static void on_cmd_cb(int revents, void* arg)
{
    struct ntrip_cmd_arg *cmd_arg = (struct ntrip_cmd_arg *)arg;
    wsocket sock = cmd_arg->socket;
    struct ntrip_caster *caster = cmd_arg->caster;
    do {
        if (revents & EV_TIMER) {
            LOG_INFO("close console(%d) due to timeout", sock);
            break;
        } else if (revents & EV_READ) {
            char buf[256];
            int n = recv(sock, buf, sizeof(buf), 0);
            if (n == WSOCKET_ERROR && wsocket_errno != WSOCKET_EWOULDBLOCK) {
                LOG_INFO("console(%d) recv error, %s", sock, wsocket_strerror(wsocket_errno));
                break;
            }
            if (n == 0) {
                LOG_INFO("console(%d) connection close", sock);
                break;
            }
            if (n < 0) { // maybe -1 since WSOCKET_EWOULDBLOCK
                break;
            }
            buf[n] = '\0';
            int   argc = 0;
            char* argv[8];
            char* p = strtok(buf, " \t\r\n");
            while (p != NULL && argc < 8) {
                argv[argc++] = p;
                p = strtok(NULL, " \t\r\n");
            }
            if (argc == 0) {
                LOG_INFO("console(%d) bad command", sock);
                SEND(sock, NTRIP_CMD_RESPONSE_BAD_COMMAND);
                break;
            }
            LOG_INFO("console(%d) cmd argc=%d, argv[0]=%s", sock, argc, argv[0]);
            // parse cmd
            if (strcmp(argv[0], "USER-LIST") == 0) {
                if (argc != 2) {
                    LOG_INFO("console(%d) bad command", sock);
                    SEND(sock, NTRIP_CMD_RESPONSE_BAD_COMMAND);
                    break;
                }
                if (strcmp(argv[1], CONSOLE_PASSWD) != 0) {
                    LOG_INFO("concole(%d) wrong pasword", sock);
                    SEND(sock, NTRIP_CMD_RESPONSE_BAD_PASSWD);
                    break;
                }
                // send response and list
                SEND(sock, "OK USER-LIST\r\n");
                tokens_user_iterate(on_iter_usertokens, (void *)sock);
                SEND(sock, "\r\n");
                LOG_INFO("console(%d) %s cmd OK.", sock, argv[0]);
            } else if (strcmp(argv[0], "USER-ADD") == 0) {
                if (argc < 4) {
                    LOG_INFO("console(%d) bad command", sock);
                    SEND(sock, NTRIP_CMD_RESPONSE_BAD_COMMAND);
                    break;
                }
                if (strcmp(argv[1], CONSOLE_PASSWD) != 0) {
                    LOG_INFO("soncole(%d) wrong pasword", sock);
                    SEND(sock, NTRIP_CMD_RESPONSE_BAD_PASSWD);
                    break;
                }
                char time[32];
                snprintf(time, sizeof(time), "%s %s", argv[3], argc == 4 ? "23:59:59" : argv[4]);
                char token[32];
                snprintf(token, sizeof(token), "%s", argv[2]);
                char *p = strchr(token, ':');
                if (p) {
                    *p = '\0';
                    int rv = tokens_user_add(token, p + 1, time);
                    if (rv == 0) {
                        SEND(sock, "OK USER-ADD\r\n\r\n");
                    } else {
                        SEND(sock, "ERROR add user failed\r\n");
                        break;
                    }
                } else {
                    SEND(sock, "ERROR invalid token\r\n");
                    break;
                }
                LOG_INFO("console(%d) %s cmd OK.", sock, argv[0]);
            } else if (strcmp(argv[0], "CLIENT-LIST") == 0) {
                if (argc != 2) {
                    LOG_INFO("console(%d) bad command", sock);
                    SEND(sock, NTRIP_CMD_RESPONSE_BAD_COMMAND);
                    break;
                }
                if (strcmp(argv[1], CONSOLE_PASSWD) != 0) {
                    LOG_INFO("concole(%d) wrong pasword", sock);
                    SEND(sock, NTRIP_CMD_RESPONSE_BAD_PASSWD);
                    break;
                }
                // send response and clients
                SEND(sock, "OK CLIENT-LIST\r\n");
                struct ntrip_agent* ag = NULL;
                TAILQ_FOREACH(ag, &caster->agents_head, entries) {
                    char line[128];
                    char time[32];
                    struct tm* timeinfo = localtime(&ag->login_time);
                    strftime(time, sizeof(time), "%Y-%m-%d %H:%M:%S", timeinfo);
                    snprintf(line, sizeof(line), "%s\t%s\t%s\r\n", ag->token, ag->ip, time);
                    SEND(sock, line);
                }
                SEND(sock, "\r\n");
                LOG_INFO("console(%d) %s cmd OK.", sock, argv[0]);
            } else if (strcmp(argv[0], "USER-UPDATE") == 0) {
                // update user token USER-UPDATE TOKEN user newpassdd
                if (argc != 4) {
                    LOG_INFO("console(%d) bad command", sock);
                    SEND(sock, NTRIP_CMD_RESPONSE_BAD_COMMAND);
                    break;
                }
                if (strcmp(argv[1], CONSOLE_PASSWD) != 0) {
                    LOG_INFO("concole(%d) wrong pasword", sock);
                    SEND(sock, NTRIP_CMD_RESPONSE_BAD_PASSWD);
                    break;
                }
                int rv = tokens_user_update(argv[2], argv[3], NULL);
                if (rv != 0) {
                    LOG_ERROR("update token failed");
                    SEND(sock, "ERROR user not found\r\n");
                    break;
                }
                SEND(sock, "OK USER-UPDATE\r\n\r\n");
                LOG_INFO("console(%d) %s cmd OK.", sock, argv[0]);
            } else if (strcmp(argv[0], "SOURCE-ADD") == 0) {
                // add ntrip entry SOURCE-ADD TOKEN server user:passwd datestr
                if (argc < 5) {
                    LOG_INFO("console(%d) bad command", sock);
                    SEND(sock, NTRIP_CMD_RESPONSE_BAD_COMMAND);
                    break;
                }
                if (strcmp(argv[1], CONSOLE_PASSWD) != 0) {
                    LOG_INFO("concole(%d) wrong pasword", sock);
                    SEND(sock, NTRIP_CMD_RESPONSE_BAD_PASSWD);
                    break;
                }
                char time[32];
                snprintf(time, sizeof(time), "%s %s", argv[4], argc == 5 ? "23:59:59" : argv[5]);
                char path[64];
                snprintf(path, sizeof(path), "%s@%s", argv[3], argv[2]);
                int rv = tokens_src_add(path, time);
                if (rv == 0) {
                    SEND(sock, "OK SOURCE-ADD\r\n\r\n");
                } else {
                    SEND(sock, "ERROR add ntrip failed\r\n");
                    break;
                }
                LOG_INFO("console(%d) %s cmd OK.", sock, argv[0]);
            } else if (strcmp(argv[0], "SOURCE-LIST") == 0) {
                if (argc != 2) {
                    LOG_INFO("console(%d) bad command", sock);
                    SEND(sock, NTRIP_CMD_RESPONSE_BAD_COMMAND);
                    break;
                }
                if (strcmp(argv[1], CONSOLE_PASSWD) != 0) {
                    LOG_INFO("concole(%d) wrong pasword", sock);
                    SEND(sock, NTRIP_CMD_RESPONSE_BAD_PASSWD);
                    break;
                }
                // send response and list
                SEND(sock, "OK SOURCE-LIST\r\n");
                tokens_src_iterate(on_iter_srctokens, (void *)sock);
                SEND(sock, "\r\n");
                LOG_INFO("console(%d) %s cmd OK.", sock, argv[0]);
            }
            LOG_INFO("close console(%d)", sock);
        }
    } while (0);
    wsocket_close(sock);
    free(cmd_arg);
}

static void cmd_accept_cb(EV_P_ ev_io *w, int revents)
{
    struct ntrip_caster *caster = (struct ntrip_caster *)((char *)w - offsetof(struct ntrip_caster, cmd_io));
    wsocket sock = INVALID_WSOCKET;
    struct sockaddr_storage agent_addr = {0};
    socklen_t agent_addrlen = sizeof(agent_addr);

    if (EV_ERROR & revents) {
        LOG_ERROR("invalid ev event with error");
        return;
    }

    sock = accept(caster->cmd_sock, (struct sockaddr *)&agent_addr, &agent_addrlen);
    if (sock == INVALID_WSOCKET) {
        LOG_ERROR("accept() error, %s", wsocket_strerror(wsocket_errno));
        return;
    }
    // set nonblocking
    wsocket_set_nonblocking(sock);
    // print connect info
    char addrbuf[NI_MAXHOST] = {0};
    char servbuf[NI_MAXSERV] = {0};
    int rv = 0;
    if ((rv = getnameinfo((struct sockaddr *)&agent_addr, agent_addrlen,
                          addrbuf, sizeof(addrbuf),
                          servbuf, sizeof(servbuf),
                          NI_NUMERICHOST | NI_NUMERICSERV)) == 0) {
        LOG_INFO("accept console(%d) from %s:%s", sock, addrbuf, servbuf);

    } else {
        LOG_ERROR("getnameinfo() error, %s", gai_strerror(rv));
    }
    struct ntrip_cmd_arg *arg = malloc(sizeof(*arg));
    arg->caster = caster;
    arg->socket = sock;
    ev_once(EV_A_ WSOCKET_GET_FD(sock), EV_READ, 2.0, on_cmd_cb, (void *)arg);
}


static FILE* m_logf = NULL;

static int log_print(void *userdata, int tag, const char *line)
{
    printf(line);
    if (m_logf) {
        fputs(line, m_logf);
        fflush(m_logf);
    }
    if (userdata) {
        struct tcpsvr *str =  userdata;
        tcpsvr_write(str, line, strlen(line));
    }
}

int main(int argc, const char *argv[])
{
    printf("qxbroadcaster version %s, %s\n", REPO_VERSION, REPO_DATE);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    {
        const char *name = argv[0];
        for (const char* p = name; *p; p++) {
            if (*p == '/' || *p == '\\') {
                name = p + 1;
            }
        }
        time_t now = time(NULL);
        char tim[32];
        strftime(tim, sizeof(tim), "%y%m%d_%H%M", localtime(&now));
        char buf[64];
        snprintf(buf, sizeof(buf), "log_%s.%s", name, tim);
        FILE* logf = fopen(buf, "w");
        m_logf = logf;
    }
    WSOCKET_INIT();
    // setup log port
    struct tcpsvr logsvr;
    tcpsvr_init(&logsvr, TCPSVR_READ_NONE);
    if (tcpsvr_open(&logsvr, "127.0.0.1", 7999) == 0) {
        ulog_init(log_print, &logsvr, ULOG_LV_ALL);
    }

    if (tokens_init(TOKENS_DB_FILE) != 0) {
        LOG_ERROR("tokens_init '%s' failed", TOKENS_DB_FILE);
        return 1;
    }
    LOG_DEBUG("fetch %d user tokens, %d source tokens",
              tokens_user_count(), tokens_src_count());

    if (proxycluster_init() != 0) {
        LOG_ERROR("init proxy cluster failed");
        return 1;
    }

    struct ev_loop* loop = EV_DEFAULT;
    static struct ntrip_caster caster = {0};
    TAILQ_INIT(&caster.listeners_head);
    TAILQ_INIT(&caster.conn_head);
    TAILQ_INIT(&caster.agents_head);
    TAILQ_INIT(&caster.sources_head);
    caster.log = &logsvr;

    int gates[3] = { 8001, 8002, 8003 };
    // create listeners
    for (int i = 0; i < sizeof(gates) / sizeof(gates[0]); i++) {
        char serv[16];
        snprintf(serv, sizeof(serv), "%d", gates[i]);
        wsocket sock = listen_on("0.0.0.0", serv);
        if (sock == INVALID_WSOCKET) {
            LOG_ERROR("setup server on 0.0.0.0:%d error.", gates[i]);
            return 1;
        }
        LOG_INFO("setup server on 0.0.0.0:%d OK.", gates[i]);
        struct ntrip_listener *listener = calloc(1, sizeof(struct ntrip_listener));
        if (listener == NULL) {
            LOG_ERROR("malloc error, %s", strerror(errno));
            return 1;
        }
        listener->socket = sock;
        listener->gate = gates[i];
        listener->caster = &caster;
        ev_io_init(&listener->io, listener_accept_cb, WSOCKET_GET_FD(sock), EV_READ);
        ev_io_start(EV_A_ &listener->io);
        TAILQ_INSERT_TAIL(&caster.listeners_head, listener, entries);
    }
    // init cmd console
    wsocket sock = listen_on("0.0.0.0", "8000");
    if (sock == INVALID_WSOCKET) {
        LOG_ERROR("setup console on 0.0.0.0:%s error.", "8000");
        return 1;
    }
    LOG_INFO("setup console on 0.0.0.0:%s OK.", "8000");
    caster.cmd_sock = sock;
    ev_io_init(&caster.cmd_io, cmd_accept_cb, WSOCKET_GET_FD(sock), EV_READ);
    ev_io_start(EV_A_ &caster.cmd_io);

    ev_timer_init(&caster.timer_check, caster_tmcheck_cb, 30, 10);
    ev_timer_start(EV_A_ &caster.timer_check);
    ev_timer_init(&caster.timer_src, caster_tmsrc_cb, 5, 1);
    ev_timer_start(EV_A_ &caster.timer_src);
    ev_timer_init(&caster.timer_log, caster_tmlog_cb, 15, 30);
    ev_timer_start(EV_A_ &caster.timer_log);

    ev_periodic_init(&caster.periodic_reload, caster_midnight_cb, 57600, 86400, NULL);
    ev_periodic_start(EV_A_ &caster.periodic_reload);

    while (1) {
        usleep(1000);
        ev_loop(loop, EVRUN_NOWAIT);
        // fetch all source ntrip data and send to client agents
        struct ntrip_source *src, *tmpsrc;
        TAILQ_FOREACH_SAFE(src, &caster.sources_head, entries, tmpsrc) {
            char buf[512];
            int rd = ntripproxy_read(src->proxy, buf, sizeof(buf));
            if (rd < 0) {
                LOG_INFO("source(%s) read error, now close it's all agents", ntripproxy_get_path(src->proxy));
                for (int i = 0; i < 2; i++) {
                    struct ntrip_agent *ag, *tmp;
                    TAILQ_FOREACH_SAFE(ag, &src->agents_head[i], src_entries, tmp) {
                        LOG_INFO("agent(%d ip=%s) close due source error", ag->socket, ag->ip);
                        caster_close_agent(EV_A_ &caster, ag);
                    }
                }
            } else if (rd > 0) {
                src->proxy_activity = time(NULL);
                for (int i = 0; i < 2; i++) {
                    unsigned char *data = buf;
                    size_t datalen = rd;
                    if (i == 0) {
                        if (src->swmagic >= 0) {
                            // backup data
                            src->agents_cache_cnt[0]  = rd;
                            memcpy(src->agents_cache[0], buf, rd);
                        } else {
                            // using backup data
                            data = src->agents_cache[0];
                            datalen = src->agents_cache_cnt[0];
                        }
                    } else if (i == 1) {
                        if (src->swmagic < 0) {
                            // backup data
                            src->agents_cache_cnt[1]  = rd;
                            memcpy(src->agents_cache[1], buf, rd);
                        } else {
                            // using backup data
                            data = src->agents_cache[1];
                            datalen = src->agents_cache_cnt[1];
                        }
                    }
                    if (datalen <= 0) {
                        continue;
                    }
                    struct ntrip_agent *ag;
                    TAILQ_FOREACH(ag, &src->agents_head[i], src_entries) {
                        if (send(ag->socket, data, datalen, 0) > 0) {
                            ag->out_bytes += rd;
                            ag->out_bps = rd * 8;
                            // ag->last_activity = ev_now(EV_A);
                        }
                    }
                }
            }
        }
    }
    proxycluster_cleanup();
    tokens_cleanup();
    WSOCKET_CLEANUP();
    return 0;
}
