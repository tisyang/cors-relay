#ifndef TOKENS_H
#define TOKENS_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif


// manage user tokens and source tokens
// 'expire' fmt "2019-08-19 23:59:59"

// init tokens module, return 0 OK, -1 error
int  tokens_init(const char *database);

// deinit tokens module
int  tokens_cleanup();

int  tokens_backup();

// ------------------ user token -------------------

// get total user token count, -1 means error
int  tokens_user_count();

// check if permit a user & passwd
bool tokens_user_permit(const char *user, const char *passwd);

// get user expire time, return 0 if error or user/passwd pair not exists
time_t tokens_user_expire(const char *user, const char *passwd);

// iterate all user token and expire date
void tokens_user_iterate(void (*iter)(void *userdata,
                                      const char *user,
                                      const char *passwd,
                                      const char *expire),
                         void *userdata);

// update an user password or expire date.
// passwd or date may be NULL, NULL will ignore, but not should both be NULL.
// return 0 means OK, -1 means error.
// if user not exists, will report error.
int  tokens_user_update(const char *user, const char *passwd, const char *expire);

// add new user password and expire date.
// return 0 OK, -1 error.
int  tokens_user_add(const char *user, const char *passwd, const char *expire);

// remove user entry.
// return 0 OK, -1 error
// if user not exists, will report OK.
int  tokens_user_delete(const char *user);

// remove out-of-date entry.
// return 0 OK, -1 error
int  tokens_user_gc();

// -------------------- src token ------------------

// get total count of src tokens.
// return -1 means error.
int   tokens_src_count();

// get used src tokens count.
// return -1 means error.
int   tokens_src_count_used();

// add new src token and it's expire date. token fmt "user:passwd@addr"
// return 0 OK, -1 error
int   tokens_src_add(const char *token, const char *expire);

// delete src token
// return 0 OK, -1 error
int   tokens_src_delete(const char *token);

// try to take usage an ide src token path. path fmt "user:passwd@addr"
// buf & bufsize: output token buffer and size.
// return NULL means could not fetch one, otherwise return buf address
char* tokens_src_take_path(char *buf, size_t bufsize);

// release usage of a src token path
void  tokens_src_release_path(const char *path);

// iterate all src tokens
void  tokens_src_iterate(void (*iterfunc)(void *userdata,
                                          const char *token,
                                          const char *expire),
                         void *userdata);


#ifdef __cplusplus
}
#endif


#endif // TOKENS_H
