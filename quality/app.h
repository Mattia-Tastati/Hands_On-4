#ifndef APP_H
#define APP_H

#include <stddef.h>
#include <stdint.h>

void read_line(const int8_t *prompt, int8_t *buf, int32_t n);
void crea_utente(void);
void effettua_login(void);
void cancella_utente(void);
void modifica_utente(void);

/* demo */
void demo_ub(void);
void demo_unspecified(void);
void demo_comment_mix(void);

#endif /* APP_H */
