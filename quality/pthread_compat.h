#ifndef PTHREAD_COMPAT_H
#define PTHREAD_COMPAT_H

#ifdef _WIN32

#include <windows.h>
#include <process.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef HANDLE pthread_t;
typedef void* (*pthread_start_routine_t)(void*);
typedef struct { int dummy; } pthread_attr_t;
typedef struct { int dummy; } pthread_mutexattr_t;
typedef CRITICAL_SECTION pthread_mutex_t;

static inline int pthread_mutex_init(pthread_mutex_t* m, const pthread_mutexattr_t* attr){ (void)attr; InitializeCriticalSection(m); return 0; }
static inline int pthread_mutex_destroy(pthread_mutex_t* m){ DeleteCriticalSection(m); return 0; }
static inline int pthread_mutex_lock(pthread_mutex_t* m){ EnterCriticalSection(m); return 0; }
static inline int pthread_mutex_unlock(pthread_mutex_t* m){ LeaveCriticalSection(m); return 0; }

struct __pthread_thunk { pthread_start_routine_t start; void* arg; };
static unsigned __stdcall __pthread_trampoline(void* p){ struct __pthread_thunk* t=(struct __pthread_thunk*)p; if(!t||!t->start) return 0u; (void)t->start(t->arg); free(t); return 0u; }
static inline int pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* (*start_routine)(void*), void* arg){
    (void)attr; if(!thread||!start_routine) return -1;
    struct __pthread_thunk* t=(struct __pthread_thunk*)malloc(sizeof *t); if(!t) return -1; t->start=start_routine; t->arg=arg;
    uintptr_t h=_beginthreadex(NULL,0,__pthread_trampoline,t,0,NULL); if(!h){ free(t); return -1; } *thread=(HANDLE)h; return 0;
}
static inline int pthread_join(pthread_t thread, void** retval){ (void)retval; DWORD r=WaitForSingleObject(thread, INFINITE); if(r==WAIT_FAILED) return -1; CloseHandle(thread); return 0; }

static inline int pthread_attr_init(pthread_attr_t* a){ (void)a; return 0; }
static inline int pthread_attr_destroy(pthread_attr_t* a){ (void)a; return 0; }
static inline int pthread_mutexattr_init(pthread_mutexattr_t* a){ (void)a; return 0; }
static inline int pthread_mutexattr_destroy(pthread_mutexattr_t* a){ (void)a; return 0; }

#ifdef __cplusplus
}
#endif

#else
#include <pthread.h>
#endif

#endif /* PTHREAD_COMPAT_H */
