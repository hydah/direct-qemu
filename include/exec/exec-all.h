/*
 * internal execution defines for qemu
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

#ifndef _EXEC_ALL_H_
#define _EXEC_ALL_H_

#include "opt-def.h"

#include "qemu-common.h"

/* allow to see translation results - the slowdown should be negligible, so we leave it */
#define DEBUG_DISAS

/* Page tracking code uses ram addresses in system mode, and virtual
   addresses in userspace mode.  Define tb_page_addr_t to be an appropriate
   type.  */
#if defined(CONFIG_USER_ONLY)
typedef abi_ulong tb_page_addr_t;
#else
typedef ram_addr_t tb_page_addr_t;
#endif

/* is_jmp field values */
#define DISAS_NEXT    0 /* next instruction can be analyzed */
#define DISAS_JUMP    1 /* only pc was modified dynamically */
#define DISAS_UPDATE  2 /* cpu state was modified dynamically */
#define DISAS_TB_JUMP 3 /* only pc was modified statically */

struct TranslationBlock;
typedef struct TranslationBlock TranslationBlock;

/* XXX: make safe guess about sizes */
#define MAX_OP_PER_INSTR 208

#if HOST_LONG_BITS == 32
#define MAX_OPC_PARAM_PER_ARG 2
#else
#define MAX_OPC_PARAM_PER_ARG 1
#endif
#define MAX_OPC_PARAM_IARGS 5
#define MAX_OPC_PARAM_OARGS 1
#define MAX_OPC_PARAM_ARGS (MAX_OPC_PARAM_IARGS + MAX_OPC_PARAM_OARGS)

/* A Call op needs up to 4 + 2N parameters on 32-bit archs,
 * and up to 4 + N parameters on 64-bit archs
 * (N = number of input arguments + output arguments).  */
#define MAX_OPC_PARAM (4 + (MAX_OPC_PARAM_PER_ARG * MAX_OPC_PARAM_ARGS))
#define OPC_BUF_SIZE 640
#define OPC_MAX_SIZE (OPC_BUF_SIZE - MAX_OP_PER_INSTR)

/* Maximum size a TCG op can expand to.  This is complicated because a
   single op may require several host instructions and register reloads.
   For now take a wild guess at 192 bytes, which should allow at least
   a couple of fixup instructions per argument.  */
#define TCG_MAX_OP_SIZE 192

#define OPPARAM_BUF_SIZE (OPC_BUF_SIZE * MAX_OPC_PARAM)

#include "qemu/log.h"

void gen_intermediate_code(CPUArchState *env, struct TranslationBlock *tb);
void gen_intermediate_code_pc(CPUArchState *env, struct TranslationBlock *tb);
void restore_state_to_opc(CPUArchState *env, struct TranslationBlock *tb,
                          int pc_pos);

void cpu_gen_init(void);
int cpu_gen_code(CPUArchState *env, struct TranslationBlock *tb);
bool cpu_restore_state(CPUArchState *env, uintptr_t searched_pc);

void QEMU_NORETURN cpu_resume_from_signal(CPUArchState *env1, void *puc);
void QEMU_NORETURN cpu_io_recompile(CPUArchState *env, uintptr_t retaddr);
TranslationBlock *tb_gen_code(CPUArchState *env, 
                              target_ulong pc, target_ulong cs_base, int flags,
                              int cflags);
void cpu_exec_init(CPUArchState *env);
void QEMU_NORETURN cpu_loop_exit(CPUArchState *env1);
int page_unprotect(target_ulong address, uintptr_t pc, void *puc);
void tb_invalidate_phys_page_range(tb_page_addr_t start, tb_page_addr_t end,
                                   int is_cpu_write_access);
void tb_invalidate_phys_range(tb_page_addr_t start, tb_page_addr_t end,
                              int is_cpu_write_access);
#if !defined(CONFIG_USER_ONLY)
/* cputlb.c */
void tlb_flush_page(CPUArchState *env, target_ulong addr);
void tlb_flush(CPUArchState *env, int flush_global);
void tlb_set_page(CPUArchState *env, target_ulong vaddr,
                  hwaddr paddr, int prot,
                  int mmu_idx, target_ulong size);
void tb_invalidate_phys_addr(hwaddr addr);
#else
static inline void tlb_flush_page(CPUArchState *env, target_ulong addr)
{
}

static inline void tlb_flush(CPUArchState *env, int flush_global)
{
}
#endif

#define CODE_GEN_ALIGN           16 /* must be >= of the size of a icache line */

#define CODE_GEN_PHYS_HASH_BITS     15
#define CODE_GEN_PHYS_HASH_SIZE     (1 << CODE_GEN_PHYS_HASH_BITS)

/* estimated block size for TB allocation */
/* XXX: use a per code average code fragment size and modulate it
   according to the host CPU */
#if defined(CONFIG_SOFTMMU)
#define CODE_GEN_AVG_BLOCK_SIZE 128
#else
#define CODE_GEN_AVG_BLOCK_SIZE 64
#endif

#if defined(__arm__) || defined(_ARCH_PPC) \
    || defined(__x86_64__) || defined(__i386__) \
    || defined(__sparc__) || defined(__aarch64__) \
    || defined(CONFIG_TCG_INTERPRETER)
#define USE_DIRECT_JUMP
#endif

#ifdef SWITCH_OPT
#define DEFAULT_SWITCH_CASE_BUFFER_SIZE (256 * 1024 * 1024)
#endif

#define NOT_TRANS_YET	0xdeadbeaf
#define CONT_TRANS_TAG	(PATCH_MAX - 1)
#define PATCH_MAX	8

#define IND_TGT_SIZE		128
#define IND_TGT_NODE_MAX	(1024*16*16)
#define IND_HASH(a)	((a >> 4) & (IND_TGT_SIZE - 1))

typedef struct ind_tgt_stat {
    uint32_t tgt_count[IND_TGT_SIZE];
} ind_tgt_stat;
extern ind_tgt_stat ind_tgt_nodes[];

struct TranslationBlock {
    target_ulong pc;   /* simulated PC corresponding to this block (EIP + CS base) */
    target_ulong cs_base; /* CS base for this block */
    uint64_t flags; /* flags defining in which context the code was generated */
    uint16_t size;      /* size of target code for this block (1 <=
                           size <= TARGET_PAGE_SIZE) */
    uint16_t cflags;    /* compile flags */
#define CF_COUNT_MASK  0x7fff
#define CF_LAST_IO     0x8000 /* Last insn may be an IO access.  */

    uint8_t *tc_ptr;    /* pointer to the translated code */
    /* next matching tb for physical address. */
    struct TranslationBlock *phys_hash_next;
    /* first and second physical page containing code. The lower bit
       of the pointer tells the index in page_next[] */
    struct TranslationBlock *page_next[2];
    tb_page_addr_t page_addr[2];

    uint32_t icount;

    uint32_t func_addr;
    uint32_t tb_tag;
    uint16_t hcode_size;      /* size of host code for this block */
    uint32_t insn_count;
    uint32_t ind_miss_count;
    uint32_t shadow_fail_count;
	uint32_t ind_replace_count;


    /* the following data are used to directly call another TB from
       the code of this one. */
    uint32_t patch_num;
    uint16_t tb_jmp_offset[PATCH_MAX]; /* offset of jump instruction */
    struct TranslationBlock *jmp_next[PATCH_MAX];

    /* indicated which tbs are jumped into this tb, 
       and from which of their jmp_stub */
    struct TranslationBlock *jmp_from[TB_FROM_MAX];
    uint8_t jmp_from_num[TB_FROM_MAX]; /* */
    uint32_t jmp_from_index;

    uint32_t prof_pos;
#ifdef IND_OPT
    uint32_t type;

    uint32_t jind_src_addr[IND_SLOT_MAX];
    uint32_t jind_dest_addr[IND_SLOT_MAX];
	/* add for mru */
	uint32_t mru_src;
	uint32_t mru_dest;
    uint32_t jmp_ind;
    uint32_t jmp_ind_index;
    uint8_t *retrans_patch_ptr;
    uint8_t *ind_enter_sieve;
#ifdef SWITCH_OPT
	uint32_t sa_base;
	uint32_t shadow_base;
	uint32_t sa_entry_sum;
	uint8_t *shadow_code_start;
    uint8_t *shadow_profile_start;
	uint32_t shadow_bound[2];
    uint32_t ind_dyn_count;
#endif

    bool     has_ind;
    bool     retransed;
    uint32_t retrans_count;
    uint32_t retrans_count_max;

    ind_tgt_stat *ind_tgt;
#endif
} __attribute__ ((aligned (32)));

#include "exec/spinlock.h"

typedef struct TBContext TBContext;

struct TBContext {

    TranslationBlock *tbs;
    TranslationBlock *tb_phys_hash[CODE_GEN_PHYS_HASH_SIZE];
    int nb_tbs;
    /* any access to the tbs or the page table must use this lock */
    spinlock_t tb_lock;

    /* statistics */
    int tb_flush_count;
    int tb_phys_invalidate_count;

    int tb_invalidated_flag;
};

static inline unsigned int tb_jmp_cache_hash_page(target_ulong pc)
{
    target_ulong tmp;
    tmp = pc ^ (pc >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS));
    return (tmp >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS)) & TB_JMP_PAGE_MASK;
}

static inline unsigned int tb_jmp_cache_hash_func(target_ulong pc)
{
    target_ulong tmp;
    tmp = pc ^ (pc >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS));
    return (((tmp >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS)) & TB_JMP_PAGE_MASK)
	    | (tmp & TB_JMP_ADDR_MASK));
}

static inline unsigned int tb_phys_hash_func(tb_page_addr_t pc)
{
    return (pc >> 2) & (CODE_GEN_PHYS_HASH_SIZE - 1);
}

void tb_free(TranslationBlock *tb);
void tb_flush(CPUArchState *env);
void tb_phys_invalidate(TranslationBlock *tb, tb_page_addr_t page_addr);

#if defined(USE_DIRECT_JUMP)

#if defined(CONFIG_TCG_INTERPRETER)
static inline void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr)
{
    /* patch the branch destination */
    *(uint32_t *)jmp_addr = addr - (jmp_addr + 4);
    /* no need to flush icache explicitly */
}
#elif defined(_ARCH_PPC)
void ppc_tb_set_jmp_target(unsigned long jmp_addr, unsigned long addr);
#define tb_set_jmp_target1 ppc_tb_set_jmp_target
#elif defined(__i386__) || defined(__x86_64__)
static inline void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr)
{
    /* patch the branch destination */
    *(uint32_t *)jmp_addr = addr - (jmp_addr + 4);
    /* no need to flush icache explicitly */
}
#elif defined(__aarch64__)
void aarch64_tb_set_jmp_target(uintptr_t jmp_addr, uintptr_t addr);
#define tb_set_jmp_target1 aarch64_tb_set_jmp_target
#elif defined(__arm__)
static inline void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr)
{
#if !QEMU_GNUC_PREREQ(4, 1)
    register unsigned long _beg __asm ("a1");
    register unsigned long _end __asm ("a2");
    register unsigned long _flg __asm ("a3");
#endif

    /* we could use a ldr pc, [pc, #-4] kind of branch and avoid the flush */
    *(uint32_t *)jmp_addr =
        (*(uint32_t *)jmp_addr & ~0xffffff)
        | (((addr - (jmp_addr + 8)) >> 2) & 0xffffff);

#if QEMU_GNUC_PREREQ(4, 1)
    __builtin___clear_cache((char *) jmp_addr, (char *) jmp_addr + 4);
#else
    /* flush icache */
    _beg = jmp_addr;
    _end = jmp_addr + 4;
    _flg = 0;
    __asm __volatile__ ("swi 0x9f0002" : : "r" (_beg), "r" (_end), "r" (_flg));
#endif
}
#elif defined(__sparc__)
void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr);
#else
#error tb_set_jmp_target1 is missing
#endif

static inline void tb_set_jmp_target(TranslationBlock *tb,
                                     int n, uintptr_t addr)
{
    uint16_t offset = tb->tb_jmp_offset[n];
    tb_set_jmp_target1((uintptr_t)(tb->tc_ptr + offset), addr);
}

#else

/* set the jump target */
static inline void tb_set_jmp_target(TranslationBlock *tb,
                                     int n, unsigned long addr)
{
    unsigned long offset;

    offset = tb->tb_jmp_offset[n];
    tb_set_jmp_target1((unsigned long)(tb->tc_ptr + offset), addr);
}

#endif

static inline void tb_add_jump(TranslationBlock *tb, int n,
                               TranslationBlock *tb_next)
{
    /* patch the native jump address */
    tb_set_jmp_target(tb, n, ((unsigned long)tb_next->tc_ptr));

    tb_add_jmp_from(tb, tb_next, n);
}

/* The return address may point to the start of the next instruction.
   Subtracting one gets us the call instruction itself.  */
#if defined(CONFIG_TCG_INTERPRETER)
extern uintptr_t tci_tb_ptr;
# define GETPC() tci_tb_ptr
#elif defined(__s390__) && !defined(__s390x__)
# define GETPC() \
    (((uintptr_t)__builtin_return_address(0) & 0x7fffffffUL) - 1)
#elif defined(__arm__)
/* Thumb return addresses have the low bit set, so we need to subtract two.
   This is still safe in ARM mode because instructions are 4 bytes.  */
# define GETPC() ((uintptr_t)__builtin_return_address(0) - 2)
#else
# define GETPC() ((uintptr_t)__builtin_return_address(0) - 1)
#endif

#if defined(CONFIG_QEMU_LDST_OPTIMIZATION) && defined(CONFIG_SOFTMMU)
/* qemu_ld/st optimization split code generation to fast and slow path, thus,
   it needs special handling for an MMU helper which is called from the slow
   path, to get the fast path's pc without any additional argument.
   It uses a tricky solution which embeds the fast path pc into the slow path.

   Code flow in slow path:
   (1) pre-process
   (2) call MMU helper
   (3) jump to (5)
   (4) fast path information (implementation specific)
   (5) post-process (e.g. stack adjust)
   (6) jump to corresponding code of the next of fast path
 */
# if defined(__i386__) || defined(__x86_64__)
/* To avoid broken disassembling, long jmp is used for embedding fast path pc,
   so that the destination is the next code of fast path, though this jmp is
   never executed.

   call MMU helper
   jmp POST_PROC (2byte)    <- GETRA()
   jmp NEXT_CODE (5byte)
   POST_PROCESS ...         <- GETRA() + 7
 */
#  define GETRA() ((uintptr_t)__builtin_return_address(0))
#  define GETPC_LDST() ((uintptr_t)(GETRA() + 7 + \
                                    *(int32_t *)((void *)GETRA() + 3) - 1))
# elif defined (_ARCH_PPC) && !defined (_ARCH_PPC64)
#  define GETRA() ((uintptr_t)__builtin_return_address(0))
#  define GETPC_LDST() ((uintptr_t) ((*(int32_t *)(GETRA() - 4)) - 1))
# elif defined(__arm__)
/* We define two insns between the return address and the branch back to
   straight-line.  Find and decode that branch insn.  */
#  define GETRA()       ((uintptr_t)__builtin_return_address(0))
#  define GETPC_LDST()  tcg_getpc_ldst(GETRA())
static inline uintptr_t tcg_getpc_ldst(uintptr_t ra)
{
    int32_t b;
    ra += 8;                    /* skip the two insns */
    b = *(int32_t *)ra;         /* load the branch insn */
    b = (b << 8) >> (8 - 2);    /* extract the displacement */
    ra += 8;                    /* branches are relative to pc+8 */
    ra += b;                    /* apply the displacement */
    ra -= 4;                    /* return a pointer into the current opcode,
                                   not the start of the next opcode  */
    return ra;
}
#elif defined(__aarch64__)
#  define GETRA()       ((uintptr_t)__builtin_return_address(0))
#  define GETPC_LDST()  tcg_getpc_ldst(GETRA())
static inline uintptr_t tcg_getpc_ldst(uintptr_t ra)
{
    int32_t b;
    ra += 4;                    /* skip one instruction */
    b = *(int32_t *)ra;         /* load the branch insn */
    b = (b << 6) >> (6 - 2);    /* extract the displacement */
    ra += b;                    /* apply the displacement  */
    ra -= 4;                    /* return a pointer into the current opcode,
                                   not the start of the next opcode  */
    return ra;
}
# else
#  error "CONFIG_QEMU_LDST_OPTIMIZATION needs GETPC_LDST() implementation!"
# endif
bool is_tcg_gen_code(uintptr_t pc_ptr);
# define GETPC_EXT() (is_tcg_gen_code(GETRA()) ? GETPC_LDST() : GETPC())
#else
# define GETPC_EXT() GETPC()
#endif

#if !defined(CONFIG_USER_ONLY)

struct MemoryRegion *iotlb_to_region(hwaddr index);
bool io_mem_read(struct MemoryRegion *mr, hwaddr addr,
                 uint64_t *pvalue, unsigned size);
bool io_mem_write(struct MemoryRegion *mr, hwaddr addr,
                  uint64_t value, unsigned size);

void tlb_fill(CPUArchState *env1, target_ulong addr, int is_write, int mmu_idx,
              uintptr_t retaddr);

#include "exec/softmmu_defs.h"

#define ACCESS_TYPE (NB_MMU_MODES + 1)
#define MEMSUFFIX _code

#define DATA_SIZE 1
#include "exec/softmmu_header.h"

#define DATA_SIZE 2
#include "exec/softmmu_header.h"

#define DATA_SIZE 4
#include "exec/softmmu_header.h"

#define DATA_SIZE 8
#include "exec/softmmu_header.h"

#undef ACCESS_TYPE
#undef MEMSUFFIX

#endif

#if defined(CONFIG_USER_ONLY)
static inline tb_page_addr_t get_page_addr_code(CPUArchState *env1, target_ulong addr)
{
    return addr;
}
#else
/* cputlb.c */
tb_page_addr_t get_page_addr_code(CPUArchState *env1, target_ulong addr);
#endif

typedef void (CPUDebugExcpHandler)(CPUArchState *env);

void cpu_set_debug_excp_handler(CPUDebugExcpHandler *handler);

/* vl.c */
extern int singlestep;

/* cpu-exec.c */
extern volatile sig_atomic_t exit_request;

/* Deterministic execution requires that IO only be performed on the last
   instruction of a TB so that interrupts take effect immediately.  */
static inline int can_do_io(CPUArchState *env)
{
    CPUState *cpu = ENV_GET_CPU(env);

    if (!use_icount) {
        return 1;
    }
    /* If not executing code then assume we are ok.  */
    if (cpu->current_tb == NULL) {
        return 1;
    }
    return env->can_do_io != 0;
}

#endif
