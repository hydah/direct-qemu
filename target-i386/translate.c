/*
 *  i386 translation
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "translate.h"
#include "cemit-inline.c"
#include "retrans-ind.h"
#include "ind-prof.h"
#include <sys/mman.h>


TranslationBlock *cur_tb;

void cemit_prof_ind(CPUX86State *env, decode_t *ds, TranslationBlock *tb,
                    uint32_t ind_type);

static void exit_stub(CPUX86State *env, TCGContext *cgc)
{
    fprintf(stderr, "exit\n");    
    prof_stat(env, cgc);
}


static void cemit_count_tgt(CPUX86State *env, TCGContext *cgc, TranslationBlock *tb);
void cemit_sieve(CPUX86State *env, TCGContext *cgc, uint32_t sieve_table);
static void cemit_sieve_nopush(CPUX86State *env, TCGContext *cgc, uint32_t sieve_table);
void cemit_exit_tb(CPUX86State *env, TCGContext *cgc, uint32_t ret_tb, uint32_t ind_type);


void note_patch(TCGContext *cgc, uint8_t *at, uint8_t *to, uint8_t *tb, 
                              uint32_t func_addr, uint32_t tb_tag)
{
#if 0
    if(tb_tag != 0)
        fprintf(stderr, "note recur:0x%x pc:0x%x\n", tb_tag, cgc->pc_ptr);
#endif
    ABORT_IF((cgc->patch_count >= PATCH_ARRAY_SIZE), "node_patch overflow\n");
    ABORT_IF((cgc->patch_num >= PATCH_MAX), "tb patch_num overflow\n");

    cgc->patch_array[cgc->patch_count].at = at;
    cgc->patch_array[cgc->patch_count].to = to;
    cgc->patch_array[cgc->patch_count].tb = tb;
    cgc->patch_array[cgc->patch_count].func_addr = func_addr;
    cgc->patch_array[cgc->patch_count].tb_tag = tb_tag;
    (cgc->patch_count)++;
    ((TranslationBlock *)tb)->patch_num++;
}



static inline void emit_push_rm(uint8_t **pcode_ptr, decode_t * ds)
{
    modrm_union modrm;
    modrm.byte = (ds->modrm).byte;
  
    modrm.parts.reg = 0x6u;
    
    if (ds->flags & DSFL_GROUP2_PREFIX)
      code_emit8(*pcode_ptr, ds->Group2_Prefix);
    
    if (ds->flags & DSFL_GROUP4_PREFIX) { 
      code_emit8(*pcode_ptr, ds->Group4_Prefix);
      abort();
    }
  
    /* Push FF /6*/
    code_emit8(*pcode_ptr, 0xffu);
    code_emit8(*pcode_ptr, modrm.byte);
  
    if (ds->need_sib) 
      code_emit8(*pcode_ptr, ds->sib.byte);
  
    switch(ds->dispBytes) {
    case 1:
      code_emit8(*pcode_ptr, ds->displacement);
      break;
    case 2:
      code_emit16(*pcode_ptr, ds->displacement);
      break;
    case 4:
      code_emit32(*pcode_ptr, ds->displacement);
      break;
    }
}

void add_sieve_entry(TCGContext *cgc, TranslationBlock *tb, int type)
{
    uint32_t next_insn, next_node, jmp_offset;
    sieve_entry *se;

    if (tb->tc_ptr == (uint8_t *)NOT_TRANS_YET)
        return;

    se = (sieve_entry *)SIEVE_HASH(cgc->sieve_hashtable, (tb->pc)<<3);

    cgc->sieve_stat[(tb->pc & SIEVE_MASK) >> 3]++;
    next_insn = (uint32_t)se + 5;
    next_node = (uint32_t)(next_insn +  se->rel);
    se->rel = (uint32_t)(cgc->sieve_code_ptr) - next_insn;

#ifdef COUNT_PROF
    uint32_t addr;
    addr = (uint32_t)&cgc->sv_travel_count;
    /* pushf */
    code_emit8(cgc->sieve_code_ptr, 0x9c);
    /* add $1, (addr) */
    code_emit8(cgc->sieve_code_ptr, 0x83);
    code_emit8(cgc->sieve_code_ptr, 0x05); /* ModRM = 00 000 101b */
    code_emit32(cgc->sieve_code_ptr, addr);
    code_emit8(cgc->sieve_code_ptr, 1);
    /* adc $0, (addr + 4) */
    code_emit8(cgc->sieve_code_ptr, 0x83);
    code_emit8(cgc->sieve_code_ptr, 0x15); /* ModRM = 00 010 101b */
    code_emit32(cgc->sieve_code_ptr, addr + 4);
    code_emit8(cgc->sieve_code_ptr, 0);
    /* popf */
    code_emit8(cgc->sieve_code_ptr, 0x9d);
#endif

    /* mov 0x4(%esp),%ecx */
    code_emit8(cgc->sieve_code_ptr, 0x8b); // 8b /r
    code_emit8(cgc->sieve_code_ptr, 0x4c); // 01 001 100
    code_emit8(cgc->sieve_code_ptr, 0x24); // 00 100 100
    code_emit8(cgc->sieve_code_ptr, 0x4);
  
    /* lea -$pc(%ecx),%ecx */
    code_emit8(cgc->sieve_code_ptr, 0x8d); // 8D /r
    code_emit8(cgc->sieve_code_ptr, 0x89); // 10 001 001 
    code_emit32(cgc->sieve_code_ptr, (-(tb->pc)));
  
    /* jecxz equal */
    code_emit8(cgc->sieve_code_ptr, 0xe3u);
    code_emit8(cgc->sieve_code_ptr, 0x05u);
  
    /* jmp $next_node */
    code_emit8(cgc->sieve_code_ptr, 0xe9);
    jmp_offset = next_node - (uint32_t)cgc->sieve_code_ptr - 4;
    code_emit32(cgc->sieve_code_ptr, jmp_offset);
  
    /* equal: */
    /* pop %ecx */
    code_emit8(cgc->sieve_code_ptr, 0x59);

    /* leal 4(%esp), %esp */
    code_emit8(cgc->sieve_code_ptr, 0x8d);
    code_emit8(cgc->sieve_code_ptr, 0x64); /*01 100 100 */
    code_emit8(cgc->sieve_code_ptr, 0x24); /*10 100 100 */
    code_emit8(cgc->sieve_code_ptr, 4);

    /* jmp se->tc_ptr */
    code_emit8(cgc->sieve_code_ptr, 0xe9);
    jmp_offset = tb->tc_ptr - cgc->sieve_code_ptr - 4;
    code_emit32(cgc->sieve_code_ptr, jmp_offset);

    ABORT_IF((cgc->sieve_code_ptr - cgc->sieve_buffer > cgc->sieve_buffer_size),
           "out of sieve buffer\n");
}


void gen_target_code(CPUX86State *env, TCGContext *cgc, TranslationBlock *tb)
{
    decode_t ds1, *ds = &ds1;
    int num_insns;
    bool cont_trans;

    cgc->pc_start = tb->pc;
    cgc->pc_ptr = cgc->pc_start;
    cgc->code_ptr = tb->tc_ptr;
    cont_trans = true;
    cur_tb = tb;
    cgc->patch_count = 0;

    SuperTransBlock *cur_stb;
    cur_stb = &(cgc->stbs[cgc->stb_count++]);
    ABORT_IF((cgc->stb_count >= STB_MAX), "stb count overflow\n");

    cur_stb->pc_start = tb->pc;
    cur_stb->tc_ptr = (uint32_t)(tb->tc_ptr);

    ///printf("start tb_gen_code cgc->pc_ptr = 0x%x\n", cgc->pc_ptr);
    for(num_insns = 0; ;num_insns++) {


        simple_disas_insn(ds, cgc->pc_ptr);


        ABORT_IF((ds->opstate & OPSTATE_ADDR16), "error: OPSTATE_ADDR16\n");

        cgc->insn_len = ds->decode_eip - cgc->pc_ptr;
        cgc->pc_ptr = ds->decode_eip;

        cont_trans = (ds->emitfn)(env, cgc, ds);

        cur_tb->insn_count++;

        /* stop translation if indicated */
        if (cont_trans == false) break;

        if ((cgc->patch_count >= PATCH_ARRAY_SIZE - 2) ||
#ifdef SIEVE_OPT
            (sieve_count >= TB_FOR_SIEVE_MAX_SIZE - 1) ||
#endif
            (num_insns >= MAX_INSNS)) {
            if(cur_tb->tc_ptr == cgc->code_ptr) {
                cur_tb->tc_ptr = (uint8_t *)NOT_TRANS_YET;
            }
            code_emit8(cgc->code_ptr, 0xe9);
            code_emit32(cgc->code_ptr, NEED_PATCH_32);
            note_patch(cgc, cgc->code_ptr - 4, (uint8_t *)cgc->pc_ptr, 
                       (uint8_t *)cur_tb, cur_tb->func_addr, NORMAL_TB_TAG);
            break;
        }
    } /* end for */
    cur_stb->pc_end = cgc->pc_ptr - 1;
    ///qemu_log("end for cgc->pc_ptr = 0x%x\n", cgc->pc_ptr);

    lazy_patch(env, cgc);

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)) {
        int disas_flags;
        qemu_log("----------------\n");
        qemu_log("IN: [size=%d] %s tb_tag: 0x%x\n",
                  cgc->pc_ptr - cgc->pc_start, 
                  lookup_symbol(cgc->pc_start), cur_tb->tb_tag);
        disas_flags = 0;
        log_target_disas(env, cgc->pc_start, cgc->pc_ptr - cgc->pc_start, disas_flags);
        qemu_log("\n");
    }
#endif
    cgc->s_code_size += (cgc->pc_ptr - cgc->pc_start);
    cgc->code_gen_ptr = cgc->code_ptr;
    ABORT_IF((cgc->code_gen_ptr - cgc->code_gen_buffer > cgc->code_gen_buffer_size), 
           "code_buffer overflow\n");
    tb->hcode_size = cgc->code_gen_ptr - tb->tc_ptr;
}

void lazy_patch(CPUX86State *env, TCGContext *cgc)
{
    int i;
    TranslationBlock *dest_tb;

    for (i = 0; i < cgc->patch_count; i++) {
        uint8_t *at, *to;
        uint32_t addr, jmp_offset, tb_tag;
        at = cgc->patch_array[i].at;
        to = cgc->patch_array[i].to;
        tb_tag = cgc->patch_array[i].tb_tag;
        dest_tb = tb_find_fast(env, (uint32_t)to, tb_tag);
        if(dest_tb && (dest_tb->tc_ptr != (uint8_t *)NOT_TRANS_YET)) {
            cgc->find_dest_count ++;
            *(uint32_t *)at = dest_tb->tc_ptr - at - 4;
            cur_tb = (TranslationBlock *)(cgc->patch_array[i].tb);
            cur_tb->patch_num --;
            cur_tb->tb_jmp_offset[cur_tb->patch_num] = at - cur_tb->tc_ptr;
            tb_add_jmp_from(cur_tb, dest_tb, cur_tb->patch_num);
        } else {
#ifdef PATCH_IN_TB
            int j;
            uint32_t s_target, jmp_target;
            SuperTransBlock *r_stb;
            TranslationBlock *new_tb;
            for(j = 0; j < STB_DEPTH; j++) {
                r_stb = (cgc->stbs_recent[(s->stb_recent_num - j) % STB_DEPTH]);
                if(r_stb == NULL) continue;
                s_target = (uint32_t)to;
                ///if(s_target >= r_stb->pc_start && s_target < r_stb->pc_ptr &&
                if(s_target >= r_stb->pc_start && 
                   s_target - r_stb->pc_start < OFF_MAX) {
                    jmp_target = r_stb->insn_offset[s_target - r_stb->pc_start];
                    if (jmp_target != 0xdeadbeaf) {
                        cgc->patch_in_tb_count ++;
                        *(uint32_t *)at = jmp_target - (uint32_t)at - 4;
                        //fprintf(stderr, "codeptr:0x%x s_tgt:0x%x jmp_tgt:0x%x\n",
                        //         (uint32_t)at, s_target, jmp_target);
                        new_tb = make_tb(env, s_target, 
                                         cgc->patch_array[i].func_addr, tb_tag);
                        new_tb->tc_ptr = jmp_target;
                        continue;
                    }
                }
            }
#endif
            if(!dest_tb) {
                make_tb(env, (uint32_t)to, cgc->patch_array[i].func_addr, tb_tag);
            }
            *(uint32_t *)at = cgc->sieve_code_ptr - at - 4;
            cur_tb = (TranslationBlock *)(cgc->patch_array[i].tb);
            cur_tb->patch_num --;
            cur_tb->tb_jmp_offset[cur_tb->patch_num] = at - cur_tb->tc_ptr;

            /* movl tb, (ret_tb) */
            addr = (uint32_t)&(env->ret_tb);
            code_emit8(cgc->sieve_code_ptr, 0xc7);
            code_emit8(cgc->sieve_code_ptr, 0x05); /* ModRM = 00 000 101b */
            code_emit32(cgc->sieve_code_ptr, addr);
            code_emit32(cgc->sieve_code_ptr, (uint32_t)cur_tb);
            /* movl patch_num, (patch_num) */
            addr = (uint32_t)&(cgc->patch_num);
            code_emit8(cgc->sieve_code_ptr, 0xc7);
            code_emit8(cgc->sieve_code_ptr, 0x05); /* ModRM = 00 000 101b */
            code_emit32(cgc->sieve_code_ptr, addr);
            code_emit32(cgc->sieve_code_ptr, cur_tb->patch_num);
            /* movl jmp_target, (env->eip) */
            addr = (uint32_t)&(env->eip);
            code_emit8(cgc->sieve_code_ptr, 0xc7u);
            code_emit8(cgc->sieve_code_ptr, 0x05u); /* ModRM = 00 000 101b */
            code_emit32(cgc->sieve_code_ptr, addr);
            code_emit32(cgc->sieve_code_ptr, (uint32_t)to);
            /* jmp tb_epilogue */
            code_emit8(cgc->sieve_code_ptr, 0xe9u);
            jmp_offset = cgc->tb_ret_addr - cgc->sieve_code_ptr - 4;
            code_emit32(cgc->sieve_code_ptr, jmp_offset);
        }
    }
}

static inline bool trans_next(CPUX86State *env, TCGContext *cgc, decode_t *ds, bool always_new_tb)
{
    TranslationBlock *tb; 
    uint32_t jmp_offset;

    always_new_tb = true;
    if (!(ds->opstate & OPSTATE_DATA32)) {
        cgc->pc_ptr = cgc->pc_ptr & 0x0000ffff;
        abort();
    }

    tb = tb_find_fast(env, cgc->pc_ptr, NORMAL_TB_TAG);
    if(tb && (tb->tc_ptr != (uint8_t *)NOT_TRANS_YET)) {
        code_emit8(cgc->code_ptr, 0xe9u);
        jmp_offset = tb->tc_ptr - cgc->code_ptr - 4;
        code_emit32(cgc->code_ptr, jmp_offset);
        cgc->end_by_transnext++;
        cur_tb->tb_jmp_offset[cur_tb->patch_num] = 
                             cgc->code_ptr - cur_tb->tc_ptr - 4;
        tb_add_jmp_from(cur_tb, tb, cur_tb->patch_num); //FIXME
        ////fprintf(stderr, "patch_num = %d\n", cur_tb->patch_num);
        return false;
    } else if(!tb) { /* no tb */
        if(always_new_tb) {
            tb = make_tb(env, cgc->pc_ptr, cur_tb->func_addr, NORMAL_TB_TAG);
            tb->tc_ptr = cgc->code_ptr;
        } else {
            if(cur_tb->patch_num > PATCH_MAX - 2) {
                tb = make_tb(env, cgc->pc_ptr, cur_tb->func_addr, NORMAL_TB_TAG);
                tb->tc_ptr = cgc->code_ptr;
            }
        }
    } else { /* tb exists, but not trans yet */
            tb->tc_ptr = cgc->code_ptr;
    }

#ifdef RETRANS_IND
    //ABORT_IF((is_retrans == true), "unexpected trans_next\n");
    tb_add_jmp_from(cur_tb, tb, CONT_TRANS_TAG);
#endif

    cur_tb = tb;
    return true;
}

#ifdef PROF_IND
#ifdef PROF_PATH
static inline void cemit_ind_count(CPUX86State *env, TCGContext *cgs, decode_t *ds)
{
    uint32_t jmp_offset;

    /* pusha */
    code_emit8(cgc->code_ptr, 0x60);
    /* pushf */
    code_emit8(cgc->code_ptr, 0x9c);
    /* push (dest) */
    emit_push_rm(&cgc->code_ptr, ds);
    /* push src */
    code_emit8(cgc->code_ptr, 0x68);
    code_emit32(cgc->code_ptr, (cgc->pc_ptr - cgc->insn_len));
    /* push cgc */
    code_emit8(cgc->code_ptr, 0x68);
    code_emit32(cgc->code_ptr, (uint32_t)cgc);
    /* call stat_tgt_add_path */
    code_emit8(cgc->code_ptr, 0xe8);
    jmp_offset = (uint32_t)stat_tgt_add_path - (uint32_t)(cgc->code_ptr) - 4;
    code_emit32(cgc->code_ptr, jmp_offset);
    /* leal %esp, 12(%esp) */
    code_emit8(cgc->code_ptr, 0x8d);
    code_emit8(cgc->code_ptr, 0x64); /*01 100 100 */
    code_emit8(cgc->code_ptr, 0x24); /*00 100 100 */
    code_emit8(cgc->code_ptr, 12);
    /* popf */
    code_emit8(cgc->code_ptr, 0x9d);
    /* popa */
    code_emit8(cgc->code_ptr, 0x61);
}
#else
static inline void cemit_ind_count(CPUX86State *env, TCGContext *cgc, decode_t *ds)
{
    uint32_t jmp_offset;
    uint32_t key;

    /* modified by heyu */
    //key = cur_tb->pc;
    key = (uint32_t)cgc->code_ptr;
    //stat_src_add(key);

    /* pusha */
    code_emit8(cgc->code_ptr, 0x60);
    /* pushf */
    code_emit8(cgc->code_ptr, 0x9c);
    /* push (dest) */
    emit_push_rm(&cgc->code_ptr, ds);
    /* push src */
    code_emit8(cgc->code_ptr, 0x68);
    code_emit32(cgc->code_ptr, key);
    /* push cur_tb */
    code_emit8(cgc->code_ptr, 0x68);
    code_emit32(cgc->code_ptr, (uint32_t)cur_tb);
    /* call stat_tgt_add */
    code_emit8(cgc->code_ptr, 0xe8);
    jmp_offset = (uint32_t)stat_tgt_add - (uint32_t)(cgc->code_ptr) - 4;
    code_emit32(cgc->code_ptr, jmp_offset);
    /* leal %esp, 12(%esp) */
    code_emit8(cgc->code_ptr, 0x8d);
    code_emit8(cgc->code_ptr, 0x64); /*01 100 100 */
    code_emit8(cgc->code_ptr, 0x24); /*10 100 100 */
    code_emit8(cgc->code_ptr, 12);
    /* popf */
    code_emit8(cgc->code_ptr, 0x9d);
    /* popa */
    code_emit8(cgc->code_ptr, 0x61);
}
#endif

static inline void cemit_rc_miss_count(CPUX86State *env, TCGContext *cgc)
{
    uint32_t jmp_offset;

    /* pusha */
    code_emit8(cgc->code_ptr, 0x60);
    /* pushf */
    code_emit8(cgc->code_ptr, 0x9c);
    /* push %36(esp) dest */
    code_emit8(cgc->code_ptr, 0xff);
    code_emit8(cgc->code_ptr, 0x74); /* 01 110 100 */
    code_emit8(cgc->code_ptr, 0x24); /* 00 100 100 */
    code_emit8(cgc->code_ptr, 36);
    /* push (src) */
    code_emit8(cgc->code_ptr, 0xffu);
    code_emit8(cgc->code_ptr, 0x35u); /* ModRM = 00 110 101b */
    code_emit32(cgc->code_ptr, (uint32_t)&cgc->last_ret_addr);
    /* call stat_tgt_add */
    code_emit8(cgc->code_ptr, 0xe8);
    jmp_offset = (uint32_t)stat_tgt_add - (uint32_t)(cgc->code_ptr) - 4;
    code_emit32(cgc->code_ptr, jmp_offset);
    /* leal %esp, 8(%esp) */
    code_emit8(cgc->code_ptr, 0x8d);
    code_emit8(cgc->code_ptr, 0x64); /*01 100 100 */
    code_emit8(cgc->code_ptr, 0x24); /*00 100 100 */
    code_emit8(cgc->code_ptr, 8);
    /* popf */
    code_emit8(cgc->code_ptr, 0x9d);
    /* popa */
    code_emit8(cgc->code_ptr, 0x61);
}
#endif

inline bool emit_normal(CPUX86State *env, TCGContext *cgc, decode_t *ds)
{
    memcpy(cgc->code_ptr, (uint8_t *)(cgc->pc_ptr - cgc->insn_len), cgc->insn_len);
    cgc->code_ptr += cgc->insn_len;
    return true;
}


#ifdef PROF_PATH
static inline void cemit_push_path(CPUX86State *env, TCGContext *cgc, bool is_ind)
{
    uint32_t addr;

    /* pushf */
    code_emit8(cgc->code_ptr, 0x9c);
    /* push %ecx */
    code_emit8(cgc->code_ptr, 0x51);
    /* movl (&index) %ecx */
    addr = (uint32_t)&(cgc->path_stack_index);
    code_emit8(cgc->code_ptr, 0x8b);
    code_emit8(cgc->code_ptr, 0x05 | (R_ECX << 3));
    code_emit32(cgc->code_ptr, addr);
    /* shl %ecx, 2 */
    code_emit8(cgc->code_ptr, 0xc1);
    code_emit8(cgc->code_ptr, 0xe0 | R_ECX); /* 11 100 ECX */
    code_emit8(cgc->code_ptr, 2);
    /* movl cur_tb, (ecx + path_stack_base) */
    addr = (uint32_t)(cgc->path_stack_base);
    code_emit8(cgc->code_ptr, 0xc7);
    code_emit8(cgc->code_ptr, 0x80 | R_ECX); /* ModRM = 10 000 ECX */
    code_emit32(cgc->code_ptr, addr);
#ifdef PROF_PATH_WO_IND
    if(is_ind == true) {
        code_emit32(cgc->code_ptr, PATH_IND_TAG);
    } else {
        code_emit32(cgc->code_ptr, (uint32_t)cur_tb);
    }
#else
    code_emit32(cgc->code_ptr, (uint32_t)cur_tb);
#endif
    /* shr %ecx, 2 */
    code_emit8(cgc->code_ptr, 0xc1);
    code_emit8(cgc->code_ptr, 0xe8 | R_ECX); /* 11 101 ECX */
    code_emit8(cgc->code_ptr, 2);
    /* add 1, %ecx */
    code_emit8(cgc->code_ptr, 0x83);
    code_emit8(cgc->code_ptr, 0xc0 | R_ECX); /* 11 000 ECX */
    code_emit8(cgc->code_ptr, 1);
    /* andl PATH_STACK_SIZE -1, %ecx */
    code_emit8(cgc->code_ptr, 0x81);
    code_emit8(cgc->code_ptr, 0xe0 | R_ECX); /* 11 100 ECX */
    code_emit32(cgc->code_ptr, PATH_STACK_SIZE - 1);
    /* movl %ecx (&index) */
    addr = (uint32_t)&(cgc->path_stack_index);
    code_emit8(cgc->code_ptr, 0x89);
    code_emit8(cgc->code_ptr, 0x05 | (R_ECX << 3));
    code_emit32(cgc->code_ptr, addr);
    /* pop %ecx */
    code_emit8(cgc->code_ptr, 0x59);
    /* popf */
    code_emit8(cgc->code_ptr, 0x9d);
}
#endif

#ifdef RAS_OPT
static inline uint8_t *cemit_push_ras(CPUX86State *env, TCGContext *cgc)
{
    uint32_t addr;
    uint8_t *patch_addr_call;
    /* push %ecx */
    code_emit8(cgc->code_ptr, 0x51);

    /* movl (&call_stack_ptr), %ecx */
    addr = (uint32_t)&(cgc->call_stack_ptr);
    code_emit8(cgc->code_ptr, 0x8b);
    code_emit8(cgc->code_ptr, 0x05 | (R_ECX << 3));
    code_emit32(cgc->code_ptr, addr);
    /* movl src_pc, 4(%ecx) */
    code_emit8(cgc->code_ptr, 0xc7);
    code_emit8(cgc->code_ptr, 0x41); /* ModRM = 01 000 001b */
    code_emit8(cgc->code_ptr, 4);
    code_emit32(cgc->code_ptr, (uint32_t)cgc->pc_ptr);
    /* leal 0x8(%ecx), %ecx (ecx += 8)*/
    code_emit8(cgc->code_ptr, 0x8d);
    code_emit8(cgc->code_ptr, 0x49); /* 01 001 001 */
    code_emit8(cgc->code_ptr, 8);
    /* movl dest_pc, (%ecx) */
    code_emit8(cgc->code_ptr, 0xc7);
    code_emit8(cgc->code_ptr, 0x01); /* ModRM = 00 000 001b */
    patch_addr_call = cgc->code_ptr;
    code_emit32(cgc->code_ptr, NEED_PATCH_32);
    /* movl %ecx, (&call_stack_ptr) */
    addr = (uint32_t)&(cgc->call_stack_ptr);
    code_emit8(cgc->code_ptr, 0x89);
    code_emit8(cgc->code_ptr, 0x05 | (R_ECX << 3));
    code_emit32(cgc->code_ptr, addr);
    /* pop ecx */
    code_emit8(cgc->code_ptr, 0x59);

    return patch_addr_call;
}

static inline uint8_t *cemit_push_ras_ind(CPUX86State *env, TCGContext *cgc)
{
    uint32_t addr;
    uint8_t *patch_addr_call;
    /* push %ecx */
    code_emit8(cgc->code_ptr, 0x51);

    /* movl (&call_stack_ptr), %ecx */
    addr = (uint32_t)&(cgc->call_stack_ptr);
    code_emit8(cgc->code_ptr, 0x8b);
    code_emit8(cgc->code_ptr, 0x05 | (R_ECX << 3));
    code_emit32(cgc->code_ptr, addr);
    /* movl src_pc, 4(%ecx) */
    code_emit8(cgc->code_ptr, 0xc7);
    code_emit8(cgc->code_ptr, 0x41); /* ModRM = 01 000 001b */
    code_emit8(cgc->code_ptr, 4);
    code_emit32(cgc->code_ptr, (uint32_t)cgc->pc_ptr);
    /* leal 0x8(%ecx), %ecx (ecx += 8)*/
    code_emit8(cgc->code_ptr, 0x8d);
    code_emit8(cgc->code_ptr, 0x49); /* 01 001 001 */
    code_emit8(cgc->code_ptr, 8);
    /* movl dest_pc, (%ecx) */
    code_emit8(cgc->code_ptr, 0xc7);
    code_emit8(cgc->code_ptr, 0x01); /* ModRM = 00 000 001b */
    patch_addr_call = cgc->code_ptr;
    code_emit32(cgc->code_ptr, NEED_PATCH_32);
    /* movl %ecx, (&call_stack_ptr) */
    addr = (uint32_t)&(cgc->call_stack_ptr);
    code_emit8(cgc->code_ptr, 0x89);
    code_emit8(cgc->code_ptr, 0x05 | (R_ECX << 3));
    code_emit32(cgc->code_ptr, addr);
    /* pop ecx */
    code_emit8(cgc->code_ptr, 0x59);

    return patch_addr_call;
}

static inline void cemit_pop_ras(CPUX86State *env, TCGContext *cgc, int imm16)
{
    uint8_t *patch_addr;
    uint32_t addr;

    INCL_COUNT(ras_dyn_count);

    /* push ecx; push edx */
    code_emit8(cgc->code_ptr, 0x51);
    code_emit8(cgc->code_ptr, 0x52);
    /* pushf */
    code_emit8(cgc->code_ptr, 0x9c);

    /* movl (&call_stack_ptr), %ecx */
    addr = (uint32_t)&(cgc->call_stack_ptr);
    code_emit8(cgc->code_ptr, 0x8b);
    code_emit8(cgc->code_ptr, 0x05 | (R_ECX << 3));
    code_emit32(cgc->code_ptr, addr);

    /* mov 12(%esp) %edx */
    code_emit8(cgc->code_ptr, 0x8b);
    code_emit8(cgc->code_ptr, 0x54); /* 01 010(EDX) 100 */
    code_emit8(cgc->code_ptr, 0x24); /* 00 100 100 */
    code_emit8(cgc->code_ptr, 12);

    /* add $-8, %ecx */
    code_emit8(cgc->code_ptr, 0x81);
    code_emit8(cgc->code_ptr, 0xc1); /* 11 000 001(ECX)*/
    code_emit32(cgc->code_ptr, -8);

    /* mov %ecx, (&call_stack_ptr) */
    addr = (uint32_t)&(cgc->call_stack_ptr);
    code_emit8(cgc->code_ptr, 0x89);
    code_emit8(cgc->code_ptr, 0x05 | (R_ECX << 3));
    code_emit32(cgc->code_ptr, addr);

    /* cmp 4(%ecx), %edx */
    code_emit8(cgc->code_ptr, 0x39);
    code_emit8(cgc->code_ptr, 0x51); /* ModRM = 01 010(EDX) 001(ECX)*/
    code_emit8(cgc->code_ptr, 4);

    /* jne not_equal; */
    code_emit8(cgc->code_ptr, 0x75);
    patch_addr = cgc->code_ptr;
    code_emit8(cgc->code_ptr, NEED_PATCH_8);

    /* movl 8(%ecx), %edx */
    code_emit8(cgc->code_ptr, 0x8b);
    code_emit8(cgc->code_ptr, 0x51); /* 01 010(EDX) 001(ECX) */
    code_emit8(cgc->code_ptr, 0x8);
    /* movl %edx, (&ret_dest_pc) */
    addr = (uint32_t)&(cgc->ret_dest_pc);
    code_emit8(cgc->code_ptr, 0x89); /* */
    code_emit8(cgc->code_ptr, 0x05 | (R_EDX << 3));
    code_emit32(cgc->code_ptr, addr);
    
    /* popf;
       pop %edx; 
       pop %ecx; 
       leal 4(esp), %esp */
    code_emit8(cgc->code_ptr, 0x9d);
    code_emit8(cgc->code_ptr, 0x5a);
    code_emit8(cgc->code_ptr, 0x59);

    code_emit8(cgc->code_ptr, 0x8d);
    code_emit8(cgc->code_ptr, 0x64); /*01 100 100 */
    code_emit8(cgc->code_ptr, 0x24); /*00 100 100 */
    code_emit8(cgc->code_ptr, 4 + imm16);

    /* jmp *(ret_dest_pc) */
    code_emit8(cgc->code_ptr, 0xff);
    addr = (uint32_t)&(cgc->ret_dest_pc);
    code_emit8(cgc->code_ptr, 0x25u); /* ModRM = 00 100 101b */
    code_emit32(cgc->code_ptr, addr);
    
    *patch_addr = cgc->code_ptr - patch_addr - 1;
    /* not_equal:
       popf;
       pop edx;
       pop ecx; */

    INCL_COUNT(ras_miss_count);

    code_emit8(cgc->code_ptr, 0x9d);
    code_emit8(cgc->code_ptr, 0x5a);
    code_emit8(cgc->code_ptr, 0x59);

    if(imm16 != 0) {
        /* pop (d->imm16-4)(%esp) */
        code_emit8(cgc->code_ptr, 0x8f);
        code_emit8(cgc->code_ptr, 0x84);
        code_emit8(cgc->code_ptr, 0x24);
        code_emit32(cgc->code_ptr, imm16 - 4);

        if((imm16 - 4) != 0) {
          /* leal (d->imm16 - 4)(%esp), %esp */
          code_emit8(cgc->code_ptr, 0x8d);
          code_emit8(cgc->code_ptr, 0xa4); /* 10 100 100 */
          code_emit8(cgc->code_ptr, 0x24); /* 00 100 100 */
          code_emit32(cgc->code_ptr, imm16 - 4);
        }
    }
}
#endif

#ifdef SIEVE_OPT
void cemit_sieve(CPUX86State *env, TCGContext *cgc, uint32_t sieve_table)
{
    /* XXX always use the hashtable in this version */
    sieve_table = (uint32_t)cgc->sieve_hashtable;

    /* push %ecx */
    code_emit8(cgc->code_ptr, 0x51);

    cemit_sieve_nopush(env, cgc, sieve_table);
}

static void cemit_sieve_nopush(CPUX86State *env, TCGContext *cgc, uint32_t sieve_table)
{
    sieve_table = (uint32_t)cgc->sieve_hashtable;

    uint32_t jmp_offset;
    /* jmp sieve_stub */
    code_emit8(cgc->code_ptr, 0xe9u);
    jmp_offset = sieve_stub - cgc->code_ptr - 4;
    code_emit32(cgc->code_ptr, jmp_offset);
}
#endif

void cemit_exit_tb(CPUX86State *env, TCGContext *cgc, uint32_t ret_tb, uint32_t ind_type)
{
    uint32_t addr, jmp_offset;

#ifdef SIEVE_OPT
    /* pop %ecx */
    code_emit8(cgc->code_ptr, 0x59);
#endif
    /* pop (env->eip) */
    addr = (uint32_t)&(env->eip);
    code_emit8(cgc->code_ptr, 0x8fu);
    code_emit8(cgc->code_ptr, 0x05u); /* ModRM = 00 000 101b */
    code_emit32(cgc->code_ptr, addr);

    if(ret_tb != -1) {

        /* movl $ret_tb, (ret_tb) */
        addr = (uint32_t)&(env->ret_tb);
        code_emit8(cgc->code_ptr, 0xc7);
        code_emit8(cgc->code_ptr, 0x05); /* ModRM = 00 000 101b */
        code_emit32(cgc->code_ptr, addr);
        code_emit32(cgc->code_ptr, ret_tb);
    }
    if(ind_type != -1) {
        /* mov m_ind_type, (&cgc->ind_type) */
        addr = (uint32_t)&(env->ind_type);
        code_emit8(cgc->code_ptr, 0xc7);
        code_emit8(cgc->code_ptr, 0x05); /* ModRM = 00 000 101b */
        code_emit32(cgc->code_ptr, addr);
        code_emit32(cgc->code_ptr, ind_type);
    }

    /* jmp tb_epilogue */
    code_emit8(cgc->code_ptr, 0xe9u);
    jmp_offset = cgc->tb_ret_addr - cgc->code_ptr - 4;
    code_emit32(cgc->code_ptr, jmp_offset);
}

#ifdef IND_OPT
/* remove the IND_TGT_TH prof code */
void ind_patch_sieve(CPUX86State *env, TCGContext *cgc1, uint8_t *enter_sieve_ptr)
{
    uint8_t *code_ptr_reserved;

    code_ptr_reserved = cgc1->code_ptr;
    cgc1->code_ptr = enter_sieve_ptr;

    cemit_sieve_nopush(env, cgc1, (uint32_t)cgc1->sieve_hashtable);

    cgc1->code_ptr = code_ptr_reserved;
}
#endif

#ifdef IND_OPT
static void cemit_ind_opt(CPUX86State *env, TCGContext *cgc, int m_ind_type)
{
    uint8_t *patch_addr[IND_SLOT_MAX];
    int i;

   // qemu_log("jind: pc:0x%x\n", cgc->pc_ptr - cgc->insn_len);
#ifdef IND_TGT_TH
    cur_tb->ind_tgt = &ind_tgt_nodes[nb_ind_tgt_nodes++];
    ABORT_IF(nb_ind_tgt_nodes > IND_TGT_NODE_MAX, "ind nodes overflow\n");
#endif

    /* push %ecx */
    code_emit8(cgc->code_ptr, 0x51);

    for(i = 0; i < IND_SLOT_MAX; i++) {
        /* mov 4(%esp), %ecx */
        code_emit8(cgc->code_ptr, 0x8b);
        code_emit8(cgc->code_ptr, 0x4c); /* 01 001(ECX) 100 */
        code_emit8(cgc->code_ptr, 0x24); /* 00 100 100 */
        code_emit8(cgc->code_ptr, 4);
        /* leal -$SPC_i(%ecx), %ecx */
        code_emit8(cgc->code_ptr, 0x8d);
        code_emit8(cgc->code_ptr, 0x89); /* 10 001 001 */
        cur_tb->jind_src_addr[i] = (uint32_t)cgc->code_ptr;
        code_emit32(cgc->code_ptr, -NEED_PATCH_32);
        /* jecxz equal */
        code_emit8(cgc->code_ptr, 0xe3);
        patch_addr[i] = cgc->code_ptr;
        code_emit8(cgc->code_ptr, NEED_PATCH_8);
    }

    if(m_ind_type == IND_TYPE_JMP) {
        INCL_COUNT(jind_nothit_count);
    } else {
        INCL_COUNT(cind_nothit_count);
    }


#ifdef RETRANS_IND
    bool tb_retransed;
    tb_retransed = is_tb_retransed(cur_tb);
    if(tb_retransed == true) {
        cgc->has_ind = true;
        cgc->ind_tb = (uint32_t)cur_tb;
    }
    cur_tb->retrans_patch_ptr = cgc->code_ptr;
    if(is_retrans == false && tb_retransed == false) {
        cemit_retrans_ind(cgc, IND_TYPE_JMP);
    }
#endif

    /* the size of exit_stub is larger than sieve_enter,
       so we can patch sieve_enter without reserve space */
    cur_tb->ind_enter_sieve = cgc->code_ptr;

#ifdef IND_TGT_TH
#ifdef RETRANS_IND
    if(is_retrans == true || tb_retransed == true) {
        cemit_count_tgt(cgc, cur_tb);
    }
#else
    cemit_count_tgt(cgc, cur_tb);
#endif
#endif

    cemit_exit_tb(env, cgc, (uint32_t)cur_tb, m_ind_type);

    uint32_t jmp_offset;
    for(i = 0; i < IND_SLOT_MAX; i++) {
        jmp_offset = cgc->code_ptr - patch_addr[i] - 1;
        ABORT_IF(jmp_offset > 0xff, "jmp_offest exceed\n");
        *patch_addr[i] = jmp_offset;
        /* pop %ecx */
        code_emit8(cgc->code_ptr, 0x59);
        /* leal 4(%esp), %esp */
        code_emit8(cgc->code_ptr, 0x8d);
        code_emit8(cgc->code_ptr, 0x64); /*01 100 100 */
        code_emit8(cgc->code_ptr, 0x24); /*10 100 100 */
        code_emit8(cgc->code_ptr, 4);
        /* jmp $TPC_i */
        code_emit8(cgc->code_ptr, 0xe9);
        cur_tb->jind_dest_addr[i] = (uint32_t)cgc->code_ptr;
        code_emit32(cgc->code_ptr, NEED_PATCH_32);
    }
}

void rebuild_profed_tb(CPUX86State *env, TCGContext *cgc, TranslationBlock *tb)
{
    uint8_t *code_ptr_reserved;

    /* clear the prediction target */
    int i;
    for(i = 0; i < IND_SLOT_MAX; i++) {
        *(uint32_t *)(tb->jind_src_addr[i]) = NEED_PATCH_32;
    }
    tb->jmp_ind_index = 0;

    /* refill the count_tgt stub */
    code_ptr_reserved = cgc->code_ptr;
    cgc->code_ptr = tb->retrans_patch_ptr;
    tb->ind_enter_sieve = tb->retrans_patch_ptr;

    cemit_count_tgt(env, cgc, tb);

    cemit_exit_tb(env, cgc, (uint32_t)cur_tb, IND_TYPE_JMP);

    cgc->code_ptr = code_ptr_reserved;
}
#endif //IND_OPT

#ifdef RET_CACHE
static inline void cemit_rc_cmp(CPUX86State *env, TCGContext *cgc, uint8_t *patch_addr_rc,
                bool is_recur) 
{
    *(uint32_t *)patch_addr_rc = (uint32_t)cgc->code_ptr;

    /* push %ecx */
    code_emit8(cgc->code_ptr, 0x51);
    /* mov 4(%esp), %ecx */
    code_emit8(cgc->code_ptr, 0x8b);
    code_emit8(cgc->code_ptr, 0x4c); /* 01 001(ECX) 100 */
    code_emit8(cgc->code_ptr, 0x24); /* 00 100 100 */
    code_emit8(cgc->code_ptr, 4);
    /* leal -pc_ptr(%ecx), %ecx */
    code_emit8(cgc->code_ptr, 0x8d);
    code_emit8(cgc->code_ptr, 0x89); /* 10 001 001 */
    code_emit32(cgc->code_ptr, -cgc->pc_ptr);
    /* jecxz equal */
    code_emit8(cgc->code_ptr, 0xe3);
    patch_addr_rc = cgc->code_ptr;
    code_emit8(cgc->code_ptr, NEED_PATCH_8);

    INCL_COUNT(rc_miss_count);

#ifdef PROF_RET
    cemit_rc_miss_count(env, cgc);
#endif

#ifdef SIEVE_OPT
    cemit_sieve_nopush(env, cgc, (uint32_t)cgc->sieve_rettable);
#else
    cemit_exit_tb(env, cgc, 0, -1);
#endif

    /* equal: */
    *patch_addr_rc = (uint8_t)(cgc->code_ptr - patch_addr_rc - 1);
    /* pop %ecx */
    code_emit8(cgc->code_ptr, 0x59);
    /* leal 4(%esp), %esp */
    code_emit8(cgc->code_ptr, 0x8d);
    code_emit8(cgc->code_ptr, 0x64); /*01 100 100 */
    code_emit8(cgc->code_ptr, 0x24); /*10 100 100 */
    code_emit8(cgc->code_ptr, 4);
}
#endif

/* extra code size = 10(rc_1) + 5(patch) + 49(rc_2) = 64 */
bool emit_call_disp(CPUX86State *env, TCGContext *cgc, decode_t *ds)
{
    uint32_t jmp_target, addr;
    bool is_recur;

    cgc->call_count++;

    ADD_INSNS_COUNT(cgc->insn_dyn_count, cur_tb->insn_count + 1);
    PUSH_PATH(cgc, false);

    jmp_target = cgc->pc_ptr + ds->immediate;

    if(cur_tb->func_addr == jmp_target) {
        is_recur = true;
    } else {
        is_recur = false;
    }

    /* push next insn */
    code_emit8(cgc->code_ptr, 0x68);
    code_emit32(cgc->code_ptr, cgc->pc_ptr);
    if (!(ds->opstate & OPSTATE_DATA32)) {
        jmp_target = jmp_target & 0x0000ffff;
        abort();
    }

#ifdef CALL_RAS_OPT
    uint8_t *patch_addr_call;
    patch_addr_call = cemit_push_ras(env, cgc);
#endif

#ifdef RET_CACHE
    uint8_t *patch_addr_rc;
    addr = RET_HASH_FUNC(cgc->ret_hash_table, jmp_target);
    /* movl ret_tgt, (&ret_cache_entry) */
    code_emit8(cgc->code_ptr, 0xc7);
    code_emit8(cgc->code_ptr, 0x05); /* ModRM = 00 000 101b */
    code_emit32(cgc->code_ptr, addr);
    patch_addr_rc = cgc->code_ptr;
    code_emit32(cgc->code_ptr, NEED_PATCH_32);
#endif

    /* jmp NEED_PATCH */
    code_emit8(cgc->code_ptr, 0xe9);
    code_emit32(cgc->code_ptr, 0x0);
    note_patch(cgc, cgc->code_ptr - 4, (uint8_t *)jmp_target, 
               (uint8_t *)cur_tb, jmp_target, NORMAL_TB_TAG);

#ifdef CALL_RAS_OPT
    *(uint32_t *)patch_addr_call = (uint32_t)cgc->code_ptr;
#endif

#ifdef RET_CACHE
    cemit_rc_cmp(env, cgc, patch_addr_rc, is_recur);
#endif
    return trans_next(env, cgc, ds, false);
}


/* extra code size = 23(rc_1) + 30(sieve) + 49(rc_2) = 102 */
bool emit_call_near_mem(CPUX86State *env, TCGContext *cgc, decode_t *ds)
{
    uint32_t addr;

    cgc->call_ind_count++;
    cur_tb->type = IND_TYPE_CALL;

    INCL_COUNT(cind_dyn_count);
    ADD_INSNS_COUNT(cgc->insn_dyn_count, cur_tb->insn_count + 1);


    bool dest_based_on_esp = false;
    if(ds->modrm.parts.reg == 0x4u) {
        dest_based_on_esp = true;
    } else if(ds->modrm.parts.mod == 0x3u) {
        if(ds->modrm.parts.rm == 0x4u)
            dest_based_on_esp = true;
    } else if(ds->modrm.parts.rm == 0x4u && ds->sib.parts.base == 0x4u) {
        dest_based_on_esp = true;
    }

    //ABORT_IF((dest_based_on_esp == true), "error dest_based on esp\n");
	if (dest_based_on_esp == true) {
		/* Push (dest) */
		emit_push_rm(&cgc->code_ptr, ds);
		/* push (%esp) */
		code_emit8(cgc->code_ptr, 0xff);
		code_emit8(cgc->code_ptr, 0x34); /* 00 110 100 */
		code_emit8(cgc->code_ptr, 0x24);/* 00 100 100 */

		/* mov cgc->pc_ptr, 4(%esp) */
		code_emit8(cgc->code_ptr, 0xc7);
		code_emit8(cgc->code_ptr, 0x44); /* 01 000 100 */
		code_emit8(cgc->code_ptr, 0x24); /* 00 100 100 */
		code_emit8(cgc->code_ptr, 0x4);
		code_emit32(cgc->code_ptr, cgc->pc_ptr);

	}
	else {
		/* Push cgc->pc_ptr */
		code_emit8(cgc->code_ptr, 0x68u);     /* PUSH */
		code_emit32(cgc->code_ptr, cgc->pc_ptr);

		/* Push (dest) */
		emit_push_rm(&cgc->code_ptr, ds);
	}


#ifdef RET_CACHE
    uint8_t *patch_addr_rc;

    /* push %ecx */
    code_emit8(cgc->code_ptr, 0x51);
    /* movl 4(%esp), %ecx */
    code_emit8(cgc->code_ptr, 0x8b);
    code_emit8(cgc->code_ptr, 0x4c); /* 01 001(ECX) 100 */
    code_emit8(cgc->code_ptr, 0x24); /* 00 100 100 */
    code_emit8(cgc->code_ptr, 4);

    /* andl $RET_HASH_MASK, %ecx */
    code_emit8(cgc->code_ptr, 0x81);
    code_emit8(cgc->code_ptr, 0xe1); /* 11 100 001(ECX) */
    code_emit32(cgc->code_ptr, RET_HASH_MASK);

    /* movl $ret_jmp_addr, &ret_hash_table[ecx*4] */
    addr = (uint32_t)&(cgc->ret_hash_table[0]);
    code_emit8(cgc->code_ptr, 0xc7);
    code_emit8(cgc->code_ptr, 0x04); /* ModRM = 00 000 100b */
    code_emit8(cgc->code_ptr, 0x8d); /* SIB = 10 001 101b */
    code_emit32(cgc->code_ptr, addr);
    patch_addr_rc = cgc->code_ptr;
    code_emit32(cgc->code_ptr, NEED_PATCH_32);

    /* pop %ecx */
    code_emit8(cgc->code_ptr, 0x59);
#endif


#ifdef CALL_IND_OPT
    cemit_ind_opt(env, cgc, IND_TYPE_CALL);
#else
#ifdef SIEVE_OPT
    cemit_sieve(env, cgc, (uint32_t)cgc->sieve_hashtable);
#endif
#endif  

#ifdef RET_CACHE
    cemit_rc_cmp(env, cgc, patch_addr_rc, false);
#endif
    return trans_next(env, cgc, ds, false);
}

/* extra code size = 6 - 1 = 5*/
bool emit_ret(CPUX86State *env, TCGContext *cgc, decode_t *ds)
{
    uint32_t addr;

    //printf("ret cgc->pc_ptr = 0x%x\n", cgc->pc_ptr);
    cgc->ret_count ++;

    ADD_INSNS_COUNT(cgc->insn_dyn_count, cur_tb->insn_count + 1);
    PUSH_PATH(cgc, true);

    INCL_COUNT(ret_dyn_count);


#ifdef CALL_RAS_OPT
    cemit_pop_ras(cgc, 0);
#endif

#ifdef RET_CACHE
#if 0
    if(cur_tb->func_addr == 0) {
        fprintf(stderr, "ret: pc=0x%x\n", cgc->pc_ptr - cgc->insn_len);
    }
#endif

#ifdef PROF_RET
    stat_src_add(cgc->pc_ptr - cgc->insn_len);
    /* mov pc, (last_ret_addr) */
    code_emit8(cgc->code_ptr, 0xc7);
    code_emit8(cgc->code_ptr, 0x05); /* ModRM = 00 000 101b */
    code_emit32(cgc->code_ptr, (uint32_t)&cgc->last_ret_addr);
    code_emit32(cgc->code_ptr, cgc->pc_ptr - cgc->insn_len);
#endif

    /* jmp *(ret_cache_entry) */
    addr = RET_HASH_FUNC(cgc->ret_hash_table, cur_tb->func_addr);
    code_emit8(cgc->code_ptr, 0xff);
    code_emit8(cgc->code_ptr, 0x25);
    code_emit32(cgc->code_ptr, addr);
#else

    cemit_sieve(env, cgc, (uint32_t)cgc->sieve_rettable);
#endif
    return false;
}

/* extra code size = 7 + 7 + 6 - 3 = 17 */
bool emit_ret_Iw(CPUX86State *env, TCGContext *cgc, decode_t *ds)
{
    uint32_t addr;
    //printf("ret_Iw cgc->pc_ptr = 0x%x\n", cgc->pc_ptr);

    cgc->retIw_count ++;
    ADD_INSNS_COUNT(cgc->insn_dyn_count, cur_tb->insn_count + 1);
    PUSH_PATH(cgc, true);

    INCL_COUNT(ret_dyn_count);
#ifdef CALL_RAS_OPT
    cemit_pop_ras(cgc, ds->imm16);
#endif

#ifdef RET_CACHE
    /* pop (d->imm16-4)(%esp) */
    code_emit8(cgc->code_ptr, 0x8f);
    code_emit8(cgc->code_ptr, 0x84);
    code_emit8(cgc->code_ptr, 0x24);
    code_emit32(cgc->code_ptr, ((uint32_t)ds->imm16) - 4);

    if((ds->imm16 - 4) != 0) {
      /* leal (d->imm16 - 4)(%esp), %esp */
      code_emit8(cgc->code_ptr, 0x8d);
      code_emit8(cgc->code_ptr, 0xa4); /* 10 100 100 */
      code_emit8(cgc->code_ptr, 0x24); /* 00 100 100 */
      code_emit32(cgc->code_ptr, (uint32_t)ds->imm16 - 4);
    }
    
    /* jmp *(ret_cache_entry) */
    addr = RET_HASH_FUNC(cgc->ret_hash_table, cur_tb->func_addr);
    code_emit8(cgc->code_ptr, 0xff);
    code_emit8(cgc->code_ptr, 0x25);
    code_emit32(cgc->code_ptr, addr);
#else
    cemit_sieve(env, cgc, (uint32_t)cgc->sieve_rettable);
#endif

    return false;
}
/* extra code size = 0 */
bool emit_jcond(CPUX86State *env, TCGContext *cgc, decode_t *ds)
{
    uint32_t jmp_target;
    ///uint8_t *jcond_addr;
    uint8_t cond;

    //printf("jcond disp cgc->pc_ptr = 0x%x\n", cgc->pc_ptr);
    cgc->jcond_count++;
    ADD_INSNS_COUNT(cgc->insn_dyn_count, cur_tb->insn_count + 1);
    PUSH_PATH(cgc, false);

    jmp_target = cgc->pc_ptr + ds->immediate;
    ///printf("jcond disp = %d\n", ds->immediate);

    if (!(ds->opstate & OPSTATE_DATA32)) {
        jmp_target = jmp_target & 0x0000ffff;
    }

    if (ds->flags & DSFL_GROUP2_PREFIX)
        code_emit8(cgc->code_ptr, ds->Group2_Prefix);

    cond = (ds->instr[0] == 0x0fu) ? ds->instr[1] : ds->instr[0];

    /* jcond NEED_PATCH */
    code_emit8(cgc->code_ptr, 0x0fu);
    code_emit8(cgc->code_ptr, (cond & 0x0fu) | 0x80);
    code_emit32(cgc->code_ptr, NEED_PATCH_32);
    note_patch(cgc, cgc->code_ptr - 4, (uint8_t *)jmp_target, 
            (uint8_t *)cur_tb, cur_tb->func_addr, NORMAL_TB_TAG);

    return trans_next(env, cgc, ds, false);
}

/* extra code size = 0 */
bool emit_other_jcond(CPUX86State *env, TCGContext *cgc, decode_t *ds)
{
    uint32_t jmp_target;
    uint8_t *patch_addr_jother;

    cgc->jothercond_count++;
    ADD_INSNS_COUNT(cgc->insn_dyn_count, cur_tb->insn_count + 1);
    PUSH_PATH(cgc, false);

    if (ds->flags & DSFL_GROUP2_PREFIX)
      code_emit8(cgc->code_ptr, ds->Group2_Prefix);
    /* jcxz, loop, loope, loopne */
    code_emit8(cgc->code_ptr, ((OpCode *)(ds->pEntry))->index);
    code_emit8(cgc->code_ptr, 0x02); /* FIXME: fixed offset*/

    code_emit8(cgc->code_ptr, 0xeb); /* jmp rel8 */
    patch_addr_jother = cgc->code_ptr;
    code_emit8(cgc->code_ptr, NEED_PATCH_8);


    jmp_target = cgc->pc_ptr + ds->immediate;
    /* jmp NEED_PATCH */
    code_emit8(cgc->code_ptr, 0xe9);
    code_emit32(cgc->code_ptr, 0x0);
    note_patch(cgc, cgc->code_ptr - 4, (uint8_t *)jmp_target, 
               (uint8_t *)cur_tb, cur_tb->func_addr, NORMAL_TB_TAG);

    *patch_addr_jother = cgc->code_ptr - patch_addr_jother - 1;

    return trans_next(env, cgc, ds, false);
}

static bool is_function_patten(uint8_t *addr)
{
    /* push %ebp */
    /* movl %esp, %ebp */
    if(*addr == 0x55 && 
       *(addr + 1) == 0x89 && *(addr + 2) == 0xe5) {
        return true;
    } else {
        return false;
    }
}

/* extra code size = 0 */
bool emit_jmp(CPUX86State *env, TCGContext *cgc, decode_t *ds)
{
    uint32_t jmp_target, addr;

    cgc->jmp_count++;
    jmp_target = cgc->pc_ptr + ds->immediate;
    //printf("jmp cgc->pc_ptr = 0x%x target=0x%x\n", cgc->pc_ptr, jmp_target);
    //printf("jmp disp = %d\n", ds->immediate);
    ADD_INSNS_COUNT(cgc->insn_dyn_count, cur_tb->insn_count + 1);
    PUSH_PATH(cgc, false);

    if (!(ds->opstate & OPSTATE_DATA32))
        jmp_target = jmp_target & 0x0000ffff;

#ifdef ACROSS_JMP
    cgc->pc_ptr = jmp_target;
    return true;
#else
#ifdef RET_CACHE
    TranslationBlock *tb;
    tb = tb_find_fast(jmp_target, NORMAL_TB_TAG);
    if(tb != NULL) {
        if(tb->func_addr != 0 && tb->func_addr != cur_tb->func_addr) {
            /* push rc_hash(cur_tb->func_addr) */
            addr = RET_HASH_FUNC(cgc->ret_hash_table, cur_tb->func_addr);
            code_emit8(cgc->code_ptr, 0xffu);
            code_emit8(cgc->code_ptr, 0x35u); /* ModRM = 00 110 101b */
            code_emit32(cgc->code_ptr, addr);
            /* pop rc_hash(tb->func_addr) */
            addr = RET_HASH_FUNC(cgc->ret_hash_table, tb->func_addr);
            code_emit8(cgc->code_ptr, 0x8fu);
            code_emit8(cgc->code_ptr, 0x05u); /* ModRM = 00 000 101b */
            code_emit32(cgc->code_ptr, addr);
        }
    }
    else {
        /* TB == NULL, maybe jump to a new function entrance */
        if(jmp_target < cur_tb->func_addr ||
           is_function_patten((uint8_t *)jmp_target) == true) {

            make_tb(env, jmp_target, jmp_target, NORMAL_TB_TAG);
            /* push rc_hash(cur_tb->func_addr) */
            addr = RET_HASH_FUNC(cgc->ret_hash_table, cur_tb->func_addr);
            code_emit8(cgc->code_ptr, 0xffu);
            code_emit8(cgc->code_ptr, 0x35u); /* ModRM = 00 110 101b */
            code_emit32(cgc->code_ptr, addr);
            /* pop rc_hash(tb->func_addr) */
            addr = RET_HASH_FUNC(cgc->ret_hash_table, jmp_target);
            code_emit8(cgc->code_ptr, 0x8fu);
            code_emit8(cgc->code_ptr, 0x05u); /* ModRM = 00 000 101b */
            code_emit32(cgc->code_ptr, addr);
        }
    }
#endif
    /* jmp NEED_PATCH */
    code_emit8(cgc->code_ptr, 0xe9);
    code_emit32(cgc->code_ptr, NEED_PATCH_32);
    note_patch(cgc, cgc->code_ptr - 4, (uint8_t *)jmp_target, 
               (uint8_t *)cur_tb, cur_tb->func_addr, NORMAL_TB_TAG);
#endif

    ///fprintf(stderr, "cgc->pc_ptr=0x%x\n", cgc->pc_ptr - cgc->insn_len);
    return false;
}


bool emit_jmp_near_mem(CPUX86State *env, TCGContext *cgc, decode_t *ds)
{
    uint32_t addr;

    cgc->j_ind_count++;
    cur_tb->type = IND_TYPE_JMP;
    INCL_COUNT(jind_dyn_count);
    ADD_INSNS_COUNT(cgc->insn_dyn_count, cur_tb->insn_count + 1);
    /* mov func_addr, (&env->ind_dest) */
    addr = (uint32_t)&(env->ind_dest);
    code_emit8(cgc->code_ptr, 0xc7);
    code_emit8(cgc->code_ptr, 0x05); /* ModRM = 00 000 101b */
    code_emit32(cgc->code_ptr, addr);
    code_emit32(cgc->code_ptr, (uint32_t)cur_tb->func_addr);



    // cannot be optimized by this method
    /* push (dest) */
    emit_push_rm(&cgc->code_ptr, ds);
#ifdef J_IND_OPT
    cemit_ind_opt(env, cgc, IND_TYPE_JMP);
#else
#ifdef SIEVE_OPT
    cemit_sieve(env, cgc, (uint32_t)cgc->sieve_hashtable);
#endif
#endif
    return false;
}

bool emit_int(CPUX86State *env, TCGContext *cgc, decode_t *ds)
{
    uint32_t jmp_offset, addr;
    uint8_t *patch_addr;
    ADD_INSNS_COUNT(cgc->insn_dyn_count, cur_tb->insn_count + 1);

    
    /* copy insn to codecache */
    if (ds->instr[1] == 0x80) {
        /* pushf */
        code_emit8(cgc->code_ptr, 0x9c); 
        /* cmp %eax ,__NR_exit_group) */
        code_emit8(cgc->code_ptr, 0x3d);
        code_emit32(cgc->code_ptr, __NR_exit_group);
        /* jne */
        code_emit8(cgc->code_ptr, 0x75);
        patch_addr = cgc->code_ptr;
        code_emit8(cgc->code_ptr, NEED_PATCH_8);
        /* push cgc */
        code_emit8(cgc->code_ptr, 0x68);
        code_emit32(cgc->code_ptr, (uint32_t)cgc);
        /* push env */
        code_emit8(cgc->code_ptr, 0x68);
        code_emit32(cgc->code_ptr, (uint32_t)env);
        /* call exit_stub */
        code_emit8(cgc->code_ptr, 0xe8);
        addr = (uint32_t)exit_stub;
        jmp_offset = addr - (uint32_t)cgc->code_ptr - 4;
        code_emit32(cgc->code_ptr, jmp_offset);

        /* leal %esp, 8(%esp) */
        code_emit8(cgc->code_ptr, 0x8d);
        code_emit8(cgc->code_ptr, 0x64); /*01 100 100 */
        code_emit8(cgc->code_ptr, 0x24); /*00 100 100 */
        code_emit8(cgc->code_ptr, 8);

        *patch_addr = cgc->code_ptr - patch_addr - 1;
        /* popf */
        code_emit8(cgc->code_ptr, 0x9d);
    }
    /* movl ds->instr[1], (env->trapnr) */
    addr = (uint32_t)&(env->trapnr);
    code_emit8(cgc->code_ptr, 0xc7u);
    code_emit8(cgc->code_ptr, 0x05u); /* ModRM = 00 000 101b */
    code_emit32(cgc->code_ptr, addr);
    code_emit32(cgc->code_ptr, (uint32_t)ds->instr[1]);

    /* movl cgc->pc_ptr, (env->eip) */
    addr = (uint32_t)&(env->eip);
    code_emit8(cgc->code_ptr, 0xc7u);
    code_emit8(cgc->code_ptr, 0x05u); /* ModRM = 00 000 101b */
    code_emit32(cgc->code_ptr, addr);
    code_emit32(cgc->code_ptr, (uint32_t)cgc->pc_ptr);

    /* movl cgc->pc_ptr, (env->ret_tb) */
    addr = (uint32_t)&(env->ret_tb);
    code_emit8(cgc->code_ptr, 0xc7u);
    code_emit8(cgc->code_ptr, 0x05u); /* ModRM = 00 000 101b */
    code_emit32(cgc->code_ptr, addr);
    code_emit32(cgc->code_ptr, (uint32_t)cur_tb);

    /* movl TYPE_SYSCALL, (env->ind_type) */
    addr = (uint32_t)&(env->ind_type);
    code_emit8(cgc->code_ptr, 0xc7u);
    code_emit8(cgc->code_ptr, 0x05u); /* ModRM = 00 000 101b */
    code_emit32(cgc->code_ptr, addr);
    code_emit32(cgc->code_ptr, TYPE_SYSCALL);

    /* jmp tb_epilogue */
    code_emit8(cgc->code_ptr, 0xe9u);
    jmp_offset = cgc->tb_ret_addr - cgc->code_ptr - 4; 
    code_emit32(cgc->code_ptr, jmp_offset);

    return false;
}

bool emit_sysenter(CPUX86State *env, TCGContext *cgc, decode_t *ds)
{
    return false;
}

#ifdef IND_OPT
static void cemit_count_tgt(CPUX86State *env, TCGContext *cgc, TranslationBlock *tb)
{
    uint8_t  *code_ptr_reserved;
    uint32_t jmp_offset;

    /* modify by heyu */
    /* a buffer to enable and disable profiling */
    //  code_emit8(cgc->code_ptr, 0xe9u);
    //code_emit32(cgc->code_ptr, 0);

    /* jmp to sieve_code_ptr */
    code_emit8(cgc->code_ptr, 0xe9u);
    jmp_offset =  cgc->sieve_code_ptr - cgc->code_ptr - 4;
    code_emit32(cgc->code_ptr, jmp_offset);

    /* pushf */
    code_emit8(cgc->sieve_code_ptr, 0x9c);
    /* movl 8(%esp), %ecx */
    code_emit8(cgc->sieve_code_ptr, 0x8b);
    code_emit8(cgc->sieve_code_ptr, 0x4c); /* 01 001(ECX) 100 */
    code_emit8(cgc->sieve_code_ptr, 0x24); /* 00 100 100 */
    code_emit8(cgc->sieve_code_ptr, 8);

    /* andl IND_THT_NODE_MAX, %ecx */
    code_emit8(cgc->sieve_code_ptr, 0x81);
    code_emit8(cgc->sieve_code_ptr, 0xe1); /* MODRM = 11 100 001 */
    /* modify by heyu */
    code_emit32(cgc->sieve_code_ptr, (IND_TGT_SIZE - 1));
    /* addl TGT_NODE, %ecx */
    code_emit8(cgc->sieve_code_ptr, 0x81);
    code_emit8(cgc->sieve_code_ptr, 0xc1); /* MODRM = 11 000 001 */
    code_emit32(cgc->sieve_code_ptr, (uint32_t)(tb->ind_tgt));
    /* incl (%ecx) */
    code_emit8(cgc->sieve_code_ptr, 0xff); 
    code_emit8(cgc->sieve_code_ptr, 0x01); /* ModRM = 00 000 001 */
    /* cmp (%ecx), IND_THRESHOLD */
    code_emit8(cgc->sieve_code_ptr, 0x81);
    code_emit8(cgc->sieve_code_ptr, 0x39); /* ModRM = 00 111 001(ECX) */
    code_emit32(cgc->sieve_code_ptr, IND_THRESHOLD);

    /* jae patch_ind */
    code_emit8(cgc->sieve_code_ptr, 0x0f);
    code_emit8(cgc->sieve_code_ptr, 0x83);
    jmp_offset =  cgc->code_ptr - cgc->sieve_code_ptr - 4;
    code_emit32(cgc->sieve_code_ptr, jmp_offset);

    /* popf */
    code_emit8(cgc->sieve_code_ptr, 0x9d);

    /* enter sieve */
    code_ptr_reserved = cgc->code_ptr;
    cgc->code_ptr = cgc->sieve_code_ptr;
    cemit_sieve_nopush(env, cgc, (uint32_t)cgc->sieve_hashtable);
    cgc->sieve_code_ptr = cgc->code_ptr;
    cgc->code_ptr = code_ptr_reserved;

    /* patch_ind: */
    /* popf */
    code_emit8(cgc->code_ptr, 0x9d);
}
#endif
