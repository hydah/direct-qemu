#ifndef __OPT_DEF_H__
#define __OPT_DEF_H__

#define SIEVE_OPT
#define SEP_SIEVE
//#define COUNT_PROF
//#define COUNT_INSN
//#define DEBUG
#define DEBUG_DISAS
//#define SHA_RODATA

#ifdef SHA_RODATA
//    #define LAZY_SHA_OPT
//    #define DATA_PROTECT
    //#define PARSE_SWITCH_CASE_CMP_NUM
    #define SWITCH_OPT
    #define SHA_THRESHOLD 1000
    #define PAGESIZE    4096
    #define GET_PAGE(v) (((int)v) & (~(PAGESIZE -1)))
    #define REG_OPT
    #define MAP_DATA_SEG
#endif
//#define DEBUG_SHA
#ifdef DEBUG_SHA
	#define SHA_DBG(...) fprintf(stderr, __VA_ARGS__);
#else
	#define SHA_DBG(...) ((void )0);
#endif

#define J_IND_OPT
#define CALL_IND_OPT
//#define RC_IND_OPT
#if defined(J_IND_OPT) || defined(CALL_IND_OPT) || defined(RC_IND_OPT)
    #define IND_OPT
#endif

#ifdef IND_OPT
    #define IND_SLOT_MAX 	3	
    //#define RETRANS_IND
#endif

#ifdef RETRANS_IND
    #define RETRANS_THRESHOLD	100000
    #define RETRANS_STACK_MAX	4096 * 4
    #define PATH_DEPTH_MAX	5
#endif

#define TB_FROM_MAX	16
#define PATH_DEPTH 4

//#define IND_TGT_TH
#define	IND_THRESHOLD	30

//#define RET_CACHE
//#define CALL_RAS_OPT
#if defined(CALL_RAS_OPT)
    #define RAS_OPT
#endif

#define TRANS_NEXT
//#define PATCH_IN_TB

#define PATH_STACK_SIZE	64
#define RETRANS_TB_TAG	0x10
#define NORMAL_TB_TAG	0x0

//#define ACROSS_JMP
//#define USE_RET_TO_ENTER_SIEVE
#define USE_CX_TO_CMP_RETCACHE

#ifdef COUNT_PROF
    #ifdef J_IND_OPT
        //#define PROF_JIND
    #endif
    #ifdef CALL_IND_OPT
        //#define PROF_CIND
    #endif
//#define COUNT_INSN
    //#define PROF_RET
#endif

#if defined(PROF_CIND) || defined(PROF_JIND) || defined(PROF_RET)
    #define PROF_IND
#endif

//#define PROF_PATH_WO_IND
#define PATH_IND_TAG	0xdeadbeef

#define STAT_NODE_MAX	2048 * 8
#define STAT_TGT_MAX	256

#define STB_MAX		1024 * 50 * 10
#ifdef PATCH_IN_TB
    #define OFF_MAX	1024 * 2
    #define STB_DEPTH	20
#endif

//#define PROF_PATH

#endif

