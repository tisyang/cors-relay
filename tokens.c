#include "tokens.h"
#include "ulog/ulog.h"

#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// internal sqlite3 connection
static sqlite3 *m_db = NULL;

int  db_init_or_upgrade(sqlite3 *db)
{
    int rc;
    char *errmsg = NULL;
    // attach memory databse
    rc  = sqlite3_exec(db,
                       "ATTACH DATABASE :memory AS db_memory;",
                       NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("attach memory db error, %s", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }
    // create user table
    rc = sqlite3_exec(db,
                      "CREATE TABLE IF NOT EXISTS tb_user("
                      "name   VARCHAR(255) PRIMARY KEY NOT NULL,"
                      "passwd VARCHAR(255) NOT NULL,"
                      "expire DATETIME NOT NULL);",
                      NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("create user table error, %s", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }
    // create src table
    rc = sqlite3_exec(db,
                      "CREATE TABLE IF NOT EXISTS tb_src("
                      "token  VARCHAR(255) PRIMARY KEY NOT NULL,"
                      "expire DATETIME NOT NULL,"
                      "flag   INT NOT NULL DEFAULT 0);",
                      NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("create src table error, %s", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }
    // create db_memory.tb_src_using table
    rc = sqlite3_exec(db,
                      "CREATE TABLE IF NOT EXISTS db_memory.tb_src_using("
                      "token VARCHAR(255) PRIMARY KEY NOT NULL,"
                      "path  VARCHAR(255) NOT NULL);",
                      NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("create using table error, %s", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }
    return 0;
}

// init tokens module, return 0 OK, -1 error
int  tokens_init(const char *database)
{
    if (m_db == NULL) {
        sqlite3 *db;
        int rc = sqlite3_open(database, &db);
        if (rc != SQLITE_OK) {
            LOG_ERROR("open db '%s' error, %s", database, sqlite3_errmsg(db));
            sqlite3_close(db);
            return -1;
        }
        if (db_init_or_upgrade(db) != 0) {
            LOG_ERROR("init/upgrade db '%s' failed", database);
            sqlite3_close(db);
            return -1;
        }
        m_db = db;
    }
    return 0;
}

// deinit tokens module
int  tokens_cleanup()
{
    if (m_db) {
        int rc;
        char *errmsg = NULL;
        // detach memory databse
        rc  = sqlite3_exec(m_db,
                           "DETACH DATABASE db_memory;",
                           NULL, NULL, &errmsg);
        if (rc != SQLITE_OK) {
            LOG_ERROR("detach memory db error, %s", errmsg);
            sqlite3_free(errmsg);
        }
        sqlite3_close(m_db);
        m_db = NULL;
    }
    return 0;
}

// ------------------ user token -------------------

// get total user token count, -1 means error
int  tokens_user_count()
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_USER_COUNT =
            "SELECT COUNT(1) FROM tb_user "
            "WHERE expire >= datetime('now', 'localtime');";
        int rc = sqlite3_prepare_v2(m_db, SQL_USER_COUNT,strlen(SQL_USER_COUNT), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare count on user table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
    }
    sqlite3_reset(stmt);
    int cnt = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        cnt = sqlite3_column_int(stmt, 0);
    }
    return cnt;
}

// check if has a user
static bool tokens_user_has(const char *user)
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_USER_PERMIT =
            "SELECT name "
            "FROM tb_user "
            "WHERE name = ?;";
        int rc = sqlite3_prepare_v2(m_db, SQL_USER_PERMIT,strlen(SQL_USER_PERMIT), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare permit on user table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
    }
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, user,   -1, SQLITE_STATIC);
    bool has = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        has = true;
    }
    return has;
}

// check if permit a user & passwd
bool tokens_user_permit(const char *user, const char *passwd)
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_USER_PERMIT =
            "SELECT name "
            "FROM tb_user "
            "WHERE name = ? AND passwd = ? AND expire >= datetime('now', 'localtime');";
        int rc = sqlite3_prepare_v2(m_db, SQL_USER_PERMIT,strlen(SQL_USER_PERMIT), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare permit on user table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
    }
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, user,   -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, passwd, -1, SQLITE_STATIC);
    bool permit = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        permit = true;
    }
    return permit;
}

time_t tokens_user_expire(const char *user, const char *passwd)
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_USER_EXPIRE =
            "SELECT strftime('%s', expire, 'utc') "
            "FROM tb_user "
            "WHERE name = ? AND passwd = ?;";
        int rc = sqlite3_prepare_v2(m_db, SQL_USER_EXPIRE,strlen(SQL_USER_EXPIRE), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare expire on user table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return 0;
        }
    }
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, user,   -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, passwd, -1, SQLITE_STATIC);
    time_t expire = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        expire = (time_t)sqlite3_column_int64(stmt, 0);
    }
    return expire;
}

// iterate all user token and expire date
void tokens_user_iterate(void (*iter)(void *userdata,
                                      const char *user,
                                      const char *passwd,
                                      const char *expire),
                         void *userdata)
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_USER_ITER =
            "SELECT name, passwd, expire FROM tb_user "
            "WHERE expire >= datetime('now', 'localtime') "
            "ORDER BY expire DESC;";
        int rc = sqlite3_prepare_v2(m_db, SQL_USER_ITER,strlen(SQL_USER_ITER), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare iterate on user table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return ;
        }
    }
    sqlite3_reset(stmt);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *user = sqlite3_column_text(stmt, 0);
        const char *passwd = sqlite3_column_text(stmt, 1);
        const char *expire = sqlite3_column_text(stmt, 2);
        if (iter) {
            iter(userdata, user, passwd, expire);
        }
    }
}

// update an user password or expire date.
// passwd or date may be NULL, NULL will ignore, but not should both be NULL.
// return 0 means OK, -1 means error.
int  tokens_user_update(const char *user, const char *passwd, const char *expire)
{
    if (passwd == NULL && expire == NULL) {
        LOG_ERROR("update user, passwd and expire should not be NULL both");
        return -1;
    }
    if (!tokens_user_has(user)) {
        LOG_ERROR("update user='%s' not exists in user table", user);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    if (passwd == NULL) {
        const char *SQL_USER_UPDATE =
            "UPDATE tb_user "
            "SET expire = ? "
            "WHERE name = ?;";
        int rc = sqlite3_prepare_v2(m_db, SQL_USER_UPDATE,strlen(SQL_USER_UPDATE), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare permit on user table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
        sqlite3_bind_text(stmt, 1, expire, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, user,   -1, SQLITE_STATIC);
    } else if (expire == NULL) {
        const char *SQL_USER_UPDATE =
            "UPDATE tb_user "
            "SET passwd = ? "
            "WHERE name = ?;";
        int rc = sqlite3_prepare_v2(m_db, SQL_USER_UPDATE,strlen(SQL_USER_UPDATE), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare permit on user table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
        sqlite3_bind_text(stmt, 1, passwd, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, user,   -1, SQLITE_STATIC);
    } else {
        const char *SQL_USER_UPDATE =
            "UPDATE tb_user "
            "SET passwd = ?, expire = ? "
            "WHERE name = ?;";
        int rc = sqlite3_prepare_v2(m_db, SQL_USER_UPDATE,strlen(SQL_USER_UPDATE), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare permit on user table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
        sqlite3_bind_text(stmt, 1, passwd, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, expire, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, user,   -1, SQLITE_STATIC);
    }
    int res = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        res = 0;
    }
    sqlite3_finalize(stmt);
    return res;
}

// add new user password and expire date.
// return 0 OK, -1 error.
int  tokens_user_add(const char *user, const char *passwd, const char *expire)
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_USER_ADD =
            "INSERT INTO tb_user (name, passwd, expire) "
            "VALUES (?, ?, ?);";
        int rc = sqlite3_prepare_v2(m_db, SQL_USER_ADD,strlen(SQL_USER_ADD), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare add on user table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
    }
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, user,   -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, passwd, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, expire, -1, SQLITE_STATIC);
    int res = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        res = 0;
    }
    return res;
}

// remove user entry.
// return 0 OK, -1 error
int  tokens_user_delete(const char *user)
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_USER_DELETE =
            "DELETE FROM tb_user WHERE name = ?;";
        int rc = sqlite3_prepare_v2(m_db, SQL_USER_DELETE,strlen(SQL_USER_DELETE), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare add on user table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
    }
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, user,   -1, SQLITE_STATIC);
    int res = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        res = 0;
    }
    return res;
}

int  tokens_user_gc()
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_USER_GC =
            "DELETE FROM tb_user "
            "WHERE expire < date('now', 'localtime');";
        int rc = sqlite3_prepare_v2(m_db, SQL_USER_GC,strlen(SQL_USER_GC), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare gc on user table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
    }
    sqlite3_reset(stmt);
    int res = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        res = 0;
    }
    return res;
}

// -------------------- src token ------------------

// get total count of src tokens.
// return -1 means error.
int   tokens_src_count()
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_SRC_COUNT =
            "SELECT COUNT(1) FROM tb_src "
            "WHERE expire >= datetime('now', 'localtime');";
        int rc = sqlite3_prepare_v2(m_db, SQL_SRC_COUNT,strlen(SQL_SRC_COUNT), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare count on src table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
    }
    sqlite3_reset(stmt);
    int cnt = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        cnt = sqlite3_column_int(stmt, 0);
    }
    return cnt;
}

// get used src tokens count.
// return -1 means error.
int   tokens_src_count_used()
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_SRC_USED_COUNT =
            "SELECT COUNT(1) FROM tb_src "
            "JOIN db_memory.tb_src_using "
            "ON db_memory.tb_src_using.token = tb_src.token;";
        int rc = sqlite3_prepare_v2(m_db, SQL_SRC_USED_COUNT,strlen(SQL_SRC_USED_COUNT), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare count on join using table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
    }
    sqlite3_reset(stmt);
    int cnt = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        cnt = sqlite3_column_int(stmt, 0);
    }
    return cnt;
}

// add new src token and it's expire date. token fmt "user:passwd@addr"
// return 0 OK, -1 error
int   tokens_src_add(const char *token, const char *expire)
{
    if (token == NULL || token[0] == '\0') {
        return -1;
    }
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_SRC_ADD =
            "INSERT INTO tb_src (token, expire) "
            "VALUES (?, ?);";
        int rc = sqlite3_prepare_v2(m_db, SQL_SRC_ADD,strlen(SQL_SRC_ADD), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare add src table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
    }
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, token,  -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, expire, -1, SQLITE_STATIC);
    int res = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        res = 0;
    }
    return res;
}

// delete src token
// return 0 OK, -1 error
int   tokens_src_delete(const char *token)
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_SRC_DELETE =
            "DELETE FROM tb_src WHERE token = ?;";
        int rc = sqlite3_prepare_v2(m_db, SQL_SRC_DELETE,strlen(SQL_SRC_DELETE), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare delete entry on src table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
    }
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, token,   -1, SQLITE_STATIC);
    int res = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        res = 0;
    }
    return res;
}


static int tokens_src_ref_using(const char *token, const char *path)
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_SRC_REF =
            "INSERT INTO db_memory.tb_src_using (token, path) "
            "VALUES(?, ?);";
        int rc = sqlite3_prepare_v2(m_db, SQL_SRC_REF,strlen(SQL_SRC_REF), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare ref using src table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
    }
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, path,  -1, SQLITE_STATIC);
    int res = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        res = 0;
    }
    return res;
}

static int tokens_src_unref_using(const char *path)
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_SRC_UNREF =
            "DELETE FROM db_memory.tb_src_using "
            "WHERE path = ?;";
        int rc = sqlite3_prepare_v2(m_db, SQL_SRC_UNREF,strlen(SQL_SRC_UNREF), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare unref using table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return -1;
        }
    }
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, path,  -1, SQLITE_STATIC);
    int res = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        res = 0;
    }
    return res;
}

char* tokens_src_take_path(char *buf, size_t bufsize)
{
    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_SRC_TAKE =
            "SELECT token FROM tb_src "
            "WHERE expire >= datetime('now', 'localtime') AND token NOT IN "
            "   (SELECT token FROM db_memory.tb_src_using) "
            "ORDER BY RANDOM() "
            "LIMIT 1;";
        int rc = sqlite3_prepare_v2(m_db, SQL_SRC_TAKE, strlen(SQL_SRC_TAKE), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare take src table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return NULL;
        }
    }
    sqlite3_reset(stmt);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *token = sqlite3_column_text(stmt, 0);
        if (token && token[0] != '\0') {
            // TODO: generate path fro token
            const char *path = token;
            if (tokens_src_ref_using(token, path) == 0) {
                snprintf(buf, bufsize, "%s", path);
                return buf;
            }
        }
    }
    return NULL;
}

void  tokens_src_release_path(const char *path)
{
    if (path) {
        tokens_src_unref_using(path);
    }
}

// iterate all src tokens
void  tokens_src_iterate(void (*iterfunc)(void *userdata,
                                          const char *token,
                                          const char *expire),
                         void *userdata)
{

    static sqlite3_stmt *stmt = NULL;
    if (stmt == NULL) {
        const char *SQL_SRC_ITER =
            "SELECT token, expire FROM tb_src; "
            "WHERE expire >= datetime('now', 'localtime') "
            "ORDER BY expire DESC;";
        int rc = sqlite3_prepare_v2(m_db, SQL_SRC_ITER,strlen(SQL_SRC_ITER), &stmt, NULL);
        if (rc != SQLITE_OK) {
            LOG_ERROR("prepare count on join using table error, %s", sqlite3_errstr(rc));
            stmt = NULL;
            return;
        }
    }
    sqlite3_reset(stmt);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *token = sqlite3_column_text(stmt, 0);
        const char *expire = sqlite3_column_text(stmt, 1);
        if (iterfunc) {
            iterfunc(userdata, token, expire);
        }
    }
}

