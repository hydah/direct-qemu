#ifndef _IND_PROF_H_
#define  _IND_PROF_H_

#include "translate.h"

#define IND_PROF_THRESHLOD	100000
#define NOT_FOUND	-1

extern bool prof_run;
extern char *exec_path;

int find_profile_node(TranslationBlock *tb);
void write_profile_info(void);
void load_profile_info(void);

void stat_src_add(uint32_t src_addr);
void stat_tgt_add(TranslationBlock *tb, uint32_t src_addr, uint32_t tgt_addr);
void stat_tgt_add_path(CPUX86State *env, uint32_t src_addr, uint32_t tgt_addr);

void prof_stat(CPUX86State *env, TCGContext *cgc);

uint32_t count_ind_tgt(ind_tgt_stat *node, uint32_t tgt);

#endif

