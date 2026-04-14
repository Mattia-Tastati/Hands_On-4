#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>
#include <stdint.h>

#define AUTH_MAX_USER 64
#define AUTH_MAX_PASS 128

int32_t auth_init(const int8_t *db_path);
int32_t auth_add(const  int8_t *username, const int8_t *password);
int32_t auth_check(const int8_t *username, const int8_t *password); /* 1 ok, 0 ko, -1 errore IO */
int32_t auth_delete(const int8_t *username);
int32_t auth_change_password(const int8_t *username, const int8_t *new_password);
int32_t  auth_rename_user(const int8_t *old_username, const int8_t *new_username);

#endif /* AUTH_H */
