/*
 *  Translated block handling
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
#ifndef TRANSLATE_ALL_H
#define TRANSLATE_ALL_H
#include <sys/mman.h>
#include "cpu.h"
#include "exec/exec-all.h"
#include "disas/disas.h"

#define code_emit8(code_emit_ptr, val) do{ \
        *(code_emit_ptr)++ = val; \
} while(0)

#define code_emit16(code_emit_ptr, val) do{ \
        *(uint16_t *)(code_emit_ptr) = (val); \
        (code_emit_ptr) += 2; \
} while(0)

#define code_emit32(code_emit_ptr, val) do{ \
        *(uint32_t *)(code_emit_ptr) = (val); \
        (code_emit_ptr) += 4; \
} while(0)



typedef struct SuperTransBlock {
    uint32_t pc_start;
    uint32_t pc_end;
    uint32_t tc_ptr;
#ifdef PATCH_IN_TB
    uint32_t insn_offset[OFF_MAX];
#endif
} SuperTransBlock;

typedef struct stat_node {
    uint32_t src_addr;
    uint32_t path[PATH_DEPTH + 1];
    /* restore the targets and the hit count of each target */
    uint32_t tgt_addr[STAT_TGT_MAX];
    uint64_t tgt_addr_hit[STAT_TGT_MAX];
    uint64_t tgt_dyn_count;
    uint32_t tgt_count;
    uint32_t tgt_recent_addr[IND_SLOT_MAX];
    uint64_t tgt_recent_hit;
    uint64_t recent_index;
    int	     profed;
    struct stat_node *next;
} stat_node;

typedef struct ind_info_node {
    uint32_t src_addr;
    uint32_t tgt_addr[IND_SLOT_MAX];
    uint32_t path[PATH_DEPTH + 1];
} ind_info_node;
typedef struct TCGContext TCGContext;

struct TCGContext {
    uint8_t *pool_cur, *pool_end;
    int nb_labels;
    int nb_globals;
    int nb_temps;

    /* goto_tb support */
    uint8_t *code_buf;
    uintptr_t *tb_next;
    uint16_t *tb_next_offset;
    uint16_t *tb_jmp_offset; /* != NULL if USE_DIRECT_JUMP */


    uint8_t *code_ptr;


#ifdef CONFIG_PROFILER
    /* profiling info */
    int64_t tb_count1;
    int64_t tb_count;
    int64_t op_count; /* total insn count */
    int op_count_max; /* max insn per TB */
    int64_t temp_count;
    int temp_count_max;
    int64_t del_op_count;
    int64_t code_in_len;
    int64_t code_out_len;
    int64_t interm_time;
    int64_t code_time;
    int64_t la_time;
    int64_t opt_time;
    int64_t restore_count;
    int64_t restore_time;
#endif

#ifdef CONFIG_DEBUG_TCG
    int temps_in_use;
    int goto_tb_issue_mask;
#endif


    /* Code generation */
    int code_gen_max_blocks;
    uint8_t *code_gen_prologue;
    uint8_t *code_gen_buffer;
    size_t code_gen_buffer_size;
    /* threshold to flush the translated code buffer */
    size_t code_gen_buffer_max_size;
    uint8_t *code_gen_ptr;
    size_t sieve_buffer_size;
    uint8_t *sieve_buffer;
    uint8_t *tb_ret_addr;

    TBContext tb_ctx;

#if defined(CONFIG_QEMU_LDST_OPTIMIZATION) && defined(CONFIG_SOFTMMU)
    /* labels info for qemu_ld/st IRs
       The labels help to generate TLB miss case codes at the end of TB */
    TCGLabelQemuLdst *qemu_ldst_labels;
    int nb_qemu_ldst_labels;
#endif
    uint32_t pc_ptr;
    uint32_t pc_start;
    uint32_t insn_len;

    SuperTransBlock stbs[STB_MAX];
#ifdef PATCH_IN_TB
    SuperTransBlock *stbs_recent[STB_DEPTH];
    uint32_t stb_recent_num;
#endif
    uint32_t stb_count;

    /* static insns count */
    uint32_t jmp_count;
    uint32_t jcond_count;
    uint32_t jothercond_count;
    uint32_t call_count;
    uint32_t call_ind_count;
    uint32_t ret_count;
    uint32_t retIw_count;
    uint32_t j_ind_count;
    uint32_t patch_in_tb_count;
    uint32_t find_dest_count;
    uint32_t s_code_size;
#ifdef SIEVE_OPT
    uint32_t sieve_stat[(1 << 16)];
#endif

    /* stb end type */
    uint32_t end_by_transnext;
#ifdef COUNT_PROF
    /* dynamic insns count */
    uint64_t insn_dyn_count;
    uint64_t cind_dyn_count;
    uint64_t jind_dyn_count;
    uint64_t ret_dyn_count;
    uint64_t ras_dyn_count;
    uint64_t ras_miss_count;
    uint64_t rc_miss_count;
    uint32_t sv_miss_count;
    uint32_t recur_dyn_count;
    uint64_t rc_ind_nothit_count;
    uint64_t rc_ind_dyn_count;
    uint64_t sv_travel_count;

    uint64_t cind_nothit_count;
    uint64_t jind_nothit_count;
	uint64_t opt_jind_nothit_count;
#endif
    stat_node stat_nodes[STAT_NODE_MAX];
    uint32_t stat_node_count;

    ind_info_node info_nodes[STAT_NODE_MAX];
    int info_node_num;

#ifdef RETRANS_IND
    uint32_t retrans_tb_count;
#endif

    FILE *fp_db;
    uint32_t tb_tag;
    uint32_t patch_num;
#ifdef SEP_SIEVE
    uint8_t *sieve_code_ptr;
#endif
#ifdef RAS_OPT
    uint32_t *call_stack_ptr;
    uint32_t *call_stack_base;
    uint32_t ret_dest_pc;
#endif
#ifdef PROF_PATH
    uint32_t *path_stack_base;
    uint32_t path_stack_index;
#endif
#ifdef RET_CACHE
    uint32_t ret_hash_table[RET_CACHE_SIZE];
    uint32_t last_ret_addr;
#endif

#ifdef VAR_TGT 
    uint32_t g_ind_miss_count;
    uint8_t *ind_tbs[IND_TB_MAX];
    uint32_t ind_tb_index;
    uint32_t tgt_replace_count;
#endif

    #define PATCH_ARRAY_SIZE	256
    patch_entry patch_array[PATCH_ARRAY_SIZE];
    uint32_t patch_count;
#ifdef SIEVE_OPT
    sieve_entry sieve_hashtable[SIEVE_SIZE];
    sieve_entry sieve_rettable[SIEVE_SIZE];
    sieve_entry sieve_jmptable[SIEVE_SIZE];
#endif
#ifdef RETRANS_IND
    bool has_ind;
    uint32_t ind_tb;
#endif
};

extern TCGContext tcg_ctx;


typedef int32_t tcg_target_long;
typedef uint32_t tcg_target_ulong;

/* Size of the L2 (and L3, etc) page tables.  */
#define L2_BITS 10
#define L2_SIZE (1 << L2_BITS)

#define P_L2_LEVELS \
    (((TARGET_PHYS_ADDR_SPACE_BITS - TARGET_PAGE_BITS - 1) / L2_BITS) + 1)

/* translate-all.c */
void tb_invalidate_phys_page_fast(tb_page_addr_t start, int len);
void cpu_unlink_tb(CPUState *cpu);
void tb_check_watchpoint(CPUArchState *env);

#endif /* TRANSLATE_ALL_H */

#ifdef SIEVE_OPT
#define TB_FOR_SIEVE_MAX_SIZE    256
extern uint32_t sieve_count;
extern uint8_t *sieve_stub;
#endif

void tcg_context_init(TCGContext *s);
void tcg_prologue_init(CPUX86State *env, TCGContext *cgc);
void tcg_func_start(TCGContext *s);
void print_maps();

/**
 * tcg_qemu_tb_exec:
 * @env: CPUArchState * for the CPU
 * @tb_ptr: address of generated code for the TB to execute
 *
 * Start executing code from a given translation block.
 * Where translation blocks have been linked, execution
 * may proceed from the given TB into successive ones.
 * Control eventually returns only when some action is needed
 * from the top-level loop: either control must pass to a TB
 * which has not yet been directly linked, or an asynchronous
 * event such as an interrupt needs handling.
 *
 * The return value is a pointer to the next TB to execute
 * (if known; otherwise zero). This pointer is assumed to be
 * 4-aligned, and the bottom two bits are used to return further
 * information:
 *  0, 1: the link between this TB and the next is via the specified
 *        TB index (0 or 1). That is, we left the TB via (the equivalent
 *        of) "goto_tb <index>". The main loop uses this to determine
 *        how to link the TB just executed to the next.
 *  2:    we are using instruction counting code generation, and we
 *        did not start executing this TB because the instruction counter
 *        would hit zero midway through it. In this case the next-TB pointer
 *        returned is the TB we were about to execute, and the caller must
 *        arrange to execute the remaining count of instructions.
 *  3:    we stopped because the CPU's exit_request flag was set
 *        (usually meaning that there is an interrupt that needs to be
 *        handled). The next-TB pointer returned is the TB we were
 *        about to execute when we noticed the pending exit request.
 *
 * If the bottom two bits indicate an exit-via-index then the CPU
 * state is correctly synchronised and ready for execution of the next
 * TB (and in particular the guest PC is the address to execute next).
 * Otherwise, we gave up on execution of this TB before it started, and
 * the caller must fix up the CPU state by calling cpu_pc_from_tb()
 * with the next-TB pointer we return.
 *
 * Note that TCG targets may use a different definition of tcg_qemu_tb_exec
 * to this default (which just calls the prologue.code emitted by
 * tcg_target_qemu_prologue()).
 */
#define TB_EXIT_MASK 3
#define TB_EXIT_IDX0 0
#define TB_EXIT_IDX1 1
#define TB_EXIT_ICOUNT_EXPIRED 2
#define TB_EXIT_REQUESTED 3

#if !defined(tcg_qemu_tb_exec)
# define tcg_qemu_tb_exec(tb_ptr) \
    ((tcg_target_ulong (*)(void *))tcg_ctx.code_gen_prologue)(tb_ptr)
#endif
