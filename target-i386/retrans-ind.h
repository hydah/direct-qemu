#ifndef _RETRANS_IND_H_
#define _RETRANS_IND_H_

#include "translate.h"

extern bool is_retrans;
extern uint32_t cur_path[];

void cemit_retrans_ind(CPUX86State *env, uint32_t ind_type);
void retrans_ind(CPUState *env, TranslationBlock *tb);
void chg_tbs_tag(TranslationBlock *tb, int depth);
bool is_tb_retransed(TranslationBlock *tb);

#endif

