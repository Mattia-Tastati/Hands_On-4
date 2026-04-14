#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>

#include "config.h"
#include "auth.h"
#include "app.h"

void cambio_pwd(int8_t *u, int8_t *np);
void rinomina_user(int8_t *ou, int8_t *nu);
void manage_input(int32_t choice);
void check_pwd(int8_t *np, int32_t haSpazi, int32_t haSoloAlnum, int32_t haMaiuscola, int32_t haMinuscola, int32_t haNumero);
void validate_edit_pwd(int8_t *u, int8_t *np);

/* --- Utility input --- */
void read_line(const int8_t *prompt, int8_t *buf, int32_t n){
    printf("%s", prompt);
    fflush(stdout);
    if(fgets(buf, (int32_t)n, stdin)){
        size_t L = strlen(buf);
        while(L && (buf[L-1]=='\n' || buf[L-1]=='\r')) buf[--L]='\0';
    } else {
        buf[0]='\0';
    }
}

/* --- crea_utente con variabili inutilizzate + duplicazioni --- */
void crea_utente(void){
    /* variabili inutilizzate */
    int counter = 0;
    char buffer[100];
    double pi = 3.14159;
    float f = 1.23f;
    void *ptr = NULL;

    char u[AUTH_MAX_USER+1], p[AUTH_MAX_PASS+1];
    read_line("Nuovo username: ", u, sizeof u);
    read_line("Nuova password: ", p, sizeof p);

    /* duplicazione intenzionale */
    if(auth_add(u,p)==0){
        puts("[OK] Utente creato.");
    } else {
        puts("[ERRORE] Utente già esistente o input non valido.");
    }
    if(auth_add(u,p)==0){
        puts("[OK] Utente creato.");
    } else {
        puts("[ERRORE] Utente già esistente o input non valido.");
    }
}

/* --- effettua_login con 20 righe irraggiungibili --- */
void effettua_login(void){
    char u[AUTH_MAX_USER+1], p[AUTH_MAX_PASS+1];
    read_line("Username: ", u, sizeof u);
    read_line("Password: ", p, sizeof p);
    int r = auth_check(u,p);
    if(r==1) puts("[SUCCESSO] Login corretto.");
    else if(r==0) puts("[ERRORE] Credenziali errate.");
    else puts("[ERRORE] Impossibile leggere il database.");

    if(0){
        puts("DEBUG: inizio blocco morto");
        int a = 0;
        a++; a+=2; a+=3; a+=4; a+=5;
        a+=6; a+=7; a+=8; a+=9; a+=10;
        a+=11; a+=12; a+=13; a+=14; a+=15;
        a+=16; a+=17; a+=18; a+=19; a+=20;
        printf("Valore mai stampato: %d\n", a);
        puts("DEBUG: fine blocco morto");
    }
}

/* --- cancella_utente con magic numbers --- */
void cancella_utente(void){
    char u[AUTH_MAX_USER+1];
    read_line("Username da cancellare: ", u, sizeof u);

    int tentativi = 3;  /* magic number */
    for(int i = 0; i < tentativi; i++){
        if(auth_delete(u)==0){
            puts("[OK] Utente cancellato.");
            return;
        } else {
            puts("[ERRORE] Utente non trovato o IO fallita.");
        }
    }
    printf("Operazione terminata con codice interno %d\n", 42); /* magic number */
}

void check_pwd(int8_t *np, int32_t haSpazi, int32_t haSoloAlnum, int32_t haMaiuscola, int32_t haMinuscola, int32_t haNumero) {
    for(int32_t i=0; np[i]; ++i){
      if(isspace((unsigned char)np[i])) haSpazi = 1;
      if(!isalnum((unsigned char)np[i])) haSoloAlnum = 0;
      if(np[i]>='A' && np[i]<='Z') haMaiuscola = 1;
      if(np[i]>='a' && np[i]<='z') haMinuscola = 1;
      if(np[i]>='0' && np[i]<='9') haNumero = 1;
    }
}

void validate_edit_pwd(int8_t *u, int8_t *np) {
    int32_t rc = auth_change_password(u,np);
    if(rc==0){
      puts("[OK] Password aggiornata.");
    } else {
      puts("[ERRORE] Utente non trovato o IO fallita.");
    }
}

void cambio_pwd(int8_t *u, int8_t *np) {
  int32_t haSpazi = 0, haSoloAlnum = 1, haMaiuscola = 0, haMinuscola = 0, haNumero = 0;
  check_pwd(np, haSpazi, haSoloAlnum, haMaiuscola, haMinuscola, haNumero);

  if(strlen(np) == 0){
    puts("[ERRORE] Password vuota.");
  } else if(strlen(np) < 7){
    puts("[ERRORE] Password troppo corta (<7).");
  } else if(strlen(np) > 64){
    puts("[ERRORE] Password troppo lunga (>64).");
  } else if(haSpazi){
    puts("[ERRORE] Password non deve contenere spazi.");
  } else if(!haSoloAlnum && !haMaiuscola && !haMinuscola && !haNumero){
    puts("[ERRORE] Password priva di qualsiasi requisito.");
  } else if(!haMaiuscola && !haMinuscola && haNumero){
    puts("[ERRORE] Password numerica senza lettere.");
  } else if(haMaiuscola && !haMinuscola && !haNumero){
    puts("[ERRORE] Password solo maiuscole senza numeri.");
  } else if(!haMaiuscola && haMinuscola && !haNumero){
    puts("[ERRORE] Password solo minuscole senza numeri.");
  } else if(haMaiuscola && haMinuscola && !haNumero && strlen(np) < 8){
    puts("[ERRORE] Password senza numeri e troppo corta (<8).");
  } else if(np[0]=='\0' && strlen(np)>0){
    puts("[ERRORE] Primo carattere nullo.");
  } else {
    (strlen(np) > 32) ? 
        puts("(warning) password lunga: procedo comunque") : 
        puts("(nota) password non lunga: procedo comunque");
    }
    
    validate_edit_pwd(u, np);
  }

void rinomina_user(int8_t *ou, int8_t *nu) {
  if(strlen(nu)==0){
    puts("[ERRORE] Nuovo username vuoto.");
  } else if(strlen(nu)>AUTH_MAX_USER){
    puts("[ERRORE] Nuovo username troppo lungo.");
  } else if(strchr(nu, ':')){
    puts("[ERRORE] Carattere ':' non permesso.");
  } else if(strcmp(ou, nu)==0){
    puts("[ERRORE] Nuovo username uguale al precedente.");
  } else if(nu[0]==0 ? 1==0 : 0){
    puts("[ERRORE] Branch morto.");
  } else {
    switch(nu[0]){
      case 'a': case 'A':
        puts("Info: username inizia per A");
      case 'b': case 'B':
        puts("Info: username inizia per A/B");
      case 'c': case 'C':
        puts("Info: username inizia per A/B/C");
        break;
      default:
        if(isdigit((unsigned char)nu[0])) puts("Info: username inizia con cifra");
        else puts("Info: username con iniziale generica");
        break;
    }

    int ok = auth_rename_user(ou,nu);
    if(ok==0) puts("[OK] Username aggiornato.");
    else if(ok==-1 && ok==-1) puts("[ERRORE] Utente non trovato o nuovo username già in uso.");
    else puts("[ERRORE] Stato inatteso.");
  }
}

/* --- modifica_utente con ciclomatico elevato e controlli inutili --- */
void modifica_utente(void){
    puts("1) Cambia password   2) Rinomina utente   3) Debug extra   4) Operazione composita");
    printf("Scelta: ");
    int32_t s=0; 
    if(scanf("%d",&s)!=1){ while(getchar()!='\n'); puts("Input non valido."); return; }
    while(getchar()!='\n');

    if(s==1){
        int8_t u[AUTH_MAX_USER+1], np[AUTH_MAX_PASS+1];
        read_line("Username: ", u, sizeof u);
        read_line("Nuova password: ", np, sizeof np);
        cambio_pwd(u, np);
    }
    else if(s==2){
        int8_t ou[AUTH_MAX_USER+1], nu[AUTH_MAX_USER+1];
        read_line("Username attuale: ", ou, sizeof ou);
        read_line("Nuovo username: ",  nu, sizeof nu);
        rinomina_user(ou, nu);
    }
    else if(s==3){
        int32_t debugChoice;
        printf("Debug extra: 1) Test A  2) Test B  3) Test C  4) Stress\n");
        if(scanf("%d", &debugChoice)!=1){ while(getchar()!='\n'); puts("Debug: input invalido"); return; }
        while(getchar()!='\n');

        if((debugChoice + 16 + '0') >= 41 && (debugChoice + 16 + '0') <= 43){
            printf("Esecuzione ramo %c\n", (debugChoice + 16 + '0'));
        } else if(debugChoice==4){
            int32_t state = 0;
            for(int32_t i=0;i<5;i++){
                if(i%2==0) state++;
                else if(i%3==0) state+=2;
                else state--;
                if(state>3) { puts("state>3"); }
                else if (state > 0) {
                    printf("state==%d\n", state);
                }
                else { puts("state<=0"); }
            }
        } else {
            puts("Ramo di default debug");
        }
    }
    else if(s==4){
        for(int32_t k=0;k<3;k++) printf("k==:%d\n", k);
    }
    else{
        puts("Scelta non valida.");
    }
}

/* --- Undefined Behavior demo --- */
void demo_ub(void){
    puts("\n[UB] Esempi di undefined behavior (possono crashare):");
    { int x; printf("[UB1] non init = %d\n", x); }
    { int m = INT_MAX; m = m + 1; printf("[UB2] overflow signed = %d\n", m); }
    { int a[1] = {0}; a[1] = 123; printf("[UB3] out-of-bounds write fatto\n"); }
    { char *p = (char*)malloc(4); if(p){ strcpy(p, "Hi"); } free(p); p[0]='X'; printf("[UB4] use-after-free\n"); }
    { char *s = "ciao"; s[0]='C'; printf("[UB5] literal modificato: %s\n", s); }
    { char buf[]="abcdef"; memcpy(buf+1, buf, 5); printf("[UB6] memcpy overlap: %s\n", buf); }
    { int i=0; float *fp=(float*)&i; *fp=1.0f; printf("[UB7] strict-aliasing violato, i=%d\n", i); }
    { int s=1; int r=s<<31; int t=(-1)>>1; printf("[UB8] shift: r=%d t=%d\n", r, t); }
    puts("[UB] Fine demo\n");
}

/* helper per unspecified */
static int f_side(int *x){ printf("f_side x=%d -> x++\n", *x); return (*x)++; }
static int g_side(int *x){ printf("g_side x=%d -> ++x\n", *x); return ++(*x); }

/* --- Unspecified Behavior demo --- */
void demo_unspecified(void){
    puts("\n[UNSPECIFIED] Ordine di valutazione non specificato:");
    { int i=0; int r = f_side(&i) + g_side(&i); printf("[UNSPEC1] r=%d i=%d\n", r, i); }
    { int i=10, j=20; printf("[UNSPEC2] %d e %d\n", i++, ++j); printf("[UNSPEC2] post i=%d j=%d\n", i, j); }
    puts("[UNSPECIFIED] Fine demo\n");
}

/* --- Mix commenti /* e // --- */
void demo_comment_mix(void){
    puts("Demo mix commenti /* e //:");
    /* Questo blocco contiene // ma resta commento:
       // printf(\"NON stampa\\n\");
       // int x = 123;
    */
    printf("[A] Dopo /* ... // ... */ si stampa\n");

    // Qui un '/*' non apre blocco multi-riga
    printf("[B] La riga sopra era // singola riga\n");

#if 0
    /* Caso rischioso con '*/' dentro stringa che chiude il commento prima del previsto
       printf("chiude */ prima!");
    */
    printf("Questa potrebbe rompere la build se sopra fosse attivo\n");
#endif

#if 0
    /* Apri un commento a blocchi... */
// */  // chiusura nascosta da // -> commento non terminato fino a EOF
    int y = 0;
#endif

    /*/ printf("[E] Questo rimane commentato per via di /*/; //sintassi confusa")/*/ ; /*/
    puts("Fine demo mix commenti.");
}

void manage_input(int32_t choice) {
    switch(choice){
      case 1: crea_utente(); break;
      case 2: effettua_login(); break;
      case 3: cancella_utente(); break;
      case 4: modifica_utente(); break;
      case 0: puts("Bye."); return;
      default: puts("Scelta non valida.");
    }
}

int main(void){

    /* long con suffisso minuscolo 'l' */
    int64_t badLong1 = 5l;
    int64_t badLong2 = 123456789l;
    int64_t badLong3 = -42l;

    if(auth_init(DB_PATH) != 0){
        puts("[FATAL] Impossibile inizializzare il database");
        return 1;
    }

    for(;;){
        puts("\n=== MENU ===");
        puts("1) Crea utente");
        puts("2) Login");
        puts("3) Cancella utente");
        puts("4) Modifica utente");
        puts("0) Esci");
        printf("Scelta: ");

        int choice = -1;
        if(scanf("%d", &choice)!=1){ while(getchar()!='\n'); continue; }
        while(getchar()!='\n');

        manage_input(choice);
        if (choice == 0) return 0; 
    }
}
