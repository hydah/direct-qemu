#ifndef _TRANSLATE_H_
#define _TRANSLATE_H_

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <asm/unistd.h>

#include "translate-all.h"

#include "decode.h"
#include "emit.h"

#define CANNOT_OPT 0 
#define CAN_OPT 1

#define DISP_MEM 3
#define REG_MEM 4
#define MEM 5
#define REG 6 

#define IS_CALL 7
#define INITIAL 0
    #define INCL_RING(c)\
    do {\
        c = (c + 1) % 6;\
    } while(0)

extern int prolog_count;
extern int nb_ind_tgt_nodes;


#ifdef COUNT_PROF
    #define INCL_COUNT(c) \
    do { \
        cemit_incl_mem64(cgc, (uint32_t)&cgc->c); \
    } while(0)
#else
    #define INCL_COUNT(c)
#endif

#define ABORT_IF(cond, msg) \
    do { \
        if(cond) { \
            fprintf(stderr, msg); \
            abort(); \
        } \
    } while(0)

#ifdef COUNT_INSN
    #define ADD_INSNS_COUNT(mem, v) \
    do { \
        /* incl insn_count */ \
        cemit_add_mem64(cgc, (uint32_t)&(mem), (uint32_t)(v)); \
    } while(0)
#else
    #define ADD_INSNS_COUNT(mem, v)
#endif

#ifdef PROF_PREV_TB
    #define SAVE_PREV_TB(cgc, mem, v) \
    do { \
        /* movl $v, (mem) */ \
        code_emit8(cgc->code_ptr, 0xc7); \
        code_emit8(cgc->code_ptr, 0x05); /* ModRM = 00 000 101b */ \
        code_emit32(cgc->code_ptr, (uint32_t)&(mem)); \
        code_emit32(cgc->code_ptr, (v)); \
    } while(0)
#else
    #define SAVE_PREV_TB(cgc, mem, v)
#endif

#ifdef PROF_PATH
    #define PUSH_PATH(cgc, is_ind) \
    do { \
        cemit_push_path(cgc, is_ind); \
    } while(0)
#else
    #define PUSH_PATH(cgc, is_ind)
#endif


extern TranslationBlock *cur_tb;
extern FILE *fout;

#endif
