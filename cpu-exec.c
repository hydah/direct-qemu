/*
 *  emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
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
#include "config.h"
#include "disas/disas.h"
#include "qemu/atomic.h"
#include "sysemu/qtest.h"

#include "ind-prof.h"
#include "retrans-ind.h"
#include "translate-all.h"

bool qemu_cpu_has_work(CPUState *cpu)
{
    return cpu_has_work(cpu);
}

void cpu_loop_exit(CPUArchState *env)
{
    CPUState *cpu = ENV_GET_CPU(env);

    cpu->current_tb = NULL;
    siglongjmp(env->jmp_env, 1);
}

/* exit the current TB from a signal handler. The host registers are
   restored in a state compatible with the CPU emulator
 */
#if defined(CONFIG_SOFTMMU)
void cpu_resume_from_signal(CPUArchState *env, void *puc)
{
    /* XXX: restore cpu registers saved in host registers */

    env->exception_index = -1;
    siglongjmp(env->jmp_env, 1);
}
#endif

void handle_syscall(CPUX86State *env, int trapnr)
{
    abi_ulong pc;
    //fprintf(stderr, "this is %s\n", __FUNCTION__);
    switch(trapnr) {
        case 0x80:
            /* linux syscall from int $0x80 */
            env->regs[R_EAX] = do_syscall(env,
                    env->regs[R_EAX],
                    env->regs[R_EBX],
                    env->regs[R_ECX],
                    env->regs[R_EDX],
                    env->regs[R_ESI],
                    env->regs[R_EDI],
                    env->regs[R_EBP]);
            break;
        default:
            pc = env->segs[R_CS].base + env->eip;
            fprintf(stderr, "qemu: 0x%08lx: unhandled CPU exception 0x%x - aborting\n",
                    (long)pc, trapnr);
            abort();
    }
}

/* Execute a TB, and fix up the CPU state afterwards if necessary */
static inline uint32_t cpu_tb_exec(CPUState *cpu, uint8_t *tb_ptr)
{
    CPUX86State *env = cpu->env_ptr;
    tcg_target_ulong next_tb = tcg_qemu_tb_exec(tb_ptr);

    if ((next_tb & TB_EXIT_MASK) > TB_EXIT_IDX1) {
        /* We didn't start executing this TB (eg because the instruction
         * counter hit zero); we must restore the guest PC to the address
         * of the start of the TB.
         */
        CPUClass *cc = CPU_GET_CLASS(cpu);
        TranslationBlock *tb = (TranslationBlock *)(next_tb & ~TB_EXIT_MASK);
        if (cc->synchronize_from_tb) {
            cc->synchronize_from_tb(cpu, tb);
        } else {
            assert(cc->set_pc);
            cc->set_pc(cpu, tb->pc);
        }
    }
    if ((next_tb & TB_EXIT_MASK) == TB_EXIT_REQUESTED) {
        /* We were asked to stop executing TBs (probably a pending
         * interrupt. We've now stopped, so clear the flag.
         */
        cpu->tcg_exit_req = 0;
    }

    if (env->ind_type == TYPE_SYSCALL) {
        handle_syscall(env, env->trapnr);
    }

    return next_tb;
}

/* Execute the code without caching the generated code. An interpreter
   could be used if available. */
static void cpu_exec_nocache(CPUArchState *env, int max_cycles,
                             TranslationBlock *orig_tb)
{
    CPUState *cpu = ENV_GET_CPU(env);
    TranslationBlock *tb;

    /* Should never happen.
       We only end up here when an existing TB is too long.  */
    if (max_cycles > CF_COUNT_MASK)
        max_cycles = CF_COUNT_MASK;

    tb = tb_gen_code(env, orig_tb->pc, orig_tb->cs_base, orig_tb->flags,
                     max_cycles);
    cpu->current_tb = tb;
    /* execute the generated code */
    cpu_tb_exec(cpu, tb->tc_ptr);
    cpu->current_tb = NULL;
    tb_phys_invalidate(tb, -1);
    tb_free(tb);
}

static TranslationBlock *tb_find_slow(CPUArchState *env, target_ulong pc,
                                      target_ulong tb_tag
                                      )
{
    TranslationBlock *tb, **ptb1;
    unsigned int h;
    tb_page_addr_t phys_pc, phys_page1;
    target_ulong virt_page2;

    tcg_ctx.tb_ctx.tb_invalidated_flag = 0;

    /* find translated block using physical mappings */
//    phys_pc = get_page_addr_code(env, pc);
 //   phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_phys_hash_func(pc);
    ptb1 = &tcg_ctx.tb_ctx.tb_phys_hash[h];
    for(;;) {
        tb = *ptb1;
        if (!tb)
            goto not_found;
        if (tb->pc == pc &&
            tb->tb_tag == tb_tag) {
                goto found;
        }
        ptb1 = &tb->phys_hash_next;
    }
 not_found:
    return NULL;

 found:
    /* we add the TB in the virtual pc hash table */
    env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
    return tb;
}

inline TranslationBlock *tb_find_fast(CPUX86State *env, uint32_t pc,  uint32_t tb_tag)
{
    TranslationBlock *tb;
    target_ulong cs_base;
    int flags;

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    //cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    tb = env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
    
    if (unlikely(!tb || tb->pc != pc || tb->tb_tag != tb_tag)) {
        tb = tb_find_slow(env, pc, tb_tag);
    }
    return tb;
}

static CPUDebugExcpHandler *debug_excp_handler;

void cpu_set_debug_excp_handler(CPUDebugExcpHandler *handler)
{
    debug_excp_handler = handler;
}

static void cpu_handle_debug_exception(CPUArchState *env)
{
    CPUWatchpoint *wp;

    if (!env->watchpoint_hit) {
        QTAILQ_FOREACH(wp, &env->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }
    if (debug_excp_handler) {
        debug_excp_handler(env);
    }
}

/* main execution loop */

static TranslationBlock *get_next_tb(CPUX86State *env, uint32_t cur_pc,
                                     TranslationBlock *prev_tb)
{
    TranslationBlock *tb;
    uint32_t tb_tag;

    tb_tag = NORMAL_TB_TAG;

    tb = tb_find_fast(env, cur_pc, tb_tag);

    if (tb == NULL) {
        /* tb doesn't exist */
        ///fprintf(stderr, "ind tb_tag: 0x%x\n", tb_tag);
        /* if no translated code available, then translate it now */
        if (env->ind_type != NOT_IND && env->ind_type != TYPE_SYSCALL) {
            switch(env->ind_type) {
              case IND_TYPE_CALL:
              case IND_TYPE_CALL_SP:
   /* if no translated code available, then translate it now */
                tb = make_tb(env, cur_pc, cur_pc, tb_tag);
                break;
              case IND_TYPE_JMP:
              case IND_TYPE_JMP_SP:
                tb = make_tb(env, cur_pc, env->ind_dest, tb_tag);
                break;
              case IND_TYPE_RET:
              case IND_TYPE_RET_SP:
                tb = make_tb(env, cur_pc, cur_pc, tb_tag);
                break;
              case IND_TYPE_RECUR:
                tb = make_tb(env, cur_pc, env->ind_dest, tb_tag);
                break;
              default:
                tb = make_tb(env, cur_pc, 0, tb_tag);
                fprintf(stderr, "default tb_tag: 0x%x\n", tb_tag);
                break;
            }
        } else {
            if(prev_tb != NULL) {
                tb = make_tb(env, cur_pc, prev_tb->func_addr, tb_tag);
            } else {
                tb = make_tb(env, cur_pc, 0, tb_tag);
                fprintf(stderr, "unexpected path: 0x%x\n", cur_pc);
            }
        }
        (void)cpu_gen_code(env, tb);
    } else if (tb->tc_ptr == (uint8_t *)NOT_TRANS_YET) {
        /* tb exists, but not translated yes */
        (void)cpu_gen_code(env, tb);
    }

    return tb;
}

#ifdef IND_OPT
static void patch_jmp_target(TranslationBlock *tb, 
                             uint32_t src_addr, uint32_t dest_addr)
{
     int jmp_index;

     //fprintf(stderr, "src:0x%x tgt:0x%x dest:0x%x\n", tb->pc, src_addr, dest_addr);
     jmp_index = tb->jmp_ind_index;
     *(uint32_t *)(tb->jind_src_addr[jmp_index]) = -src_addr;
     *(uint32_t *)(tb->jind_dest_addr[jmp_index]) =
          dest_addr - tb->jind_dest_addr[jmp_index] - 4;
     tb->jmp_ind = 0;
     tb->jmp_ind_index++;
}

static void patch_ind_opt(CPUX86State *env, TCGContext *cgc, TranslationBlock *prev_tb, TranslationBlock *tb)
{
    uint32_t tgt_addr;

    tgt_addr = env->eip;

    if(prev_tb->jmp_ind_index < IND_SLOT_MAX) {
        patch_jmp_target(prev_tb, tgt_addr, (uint32_t)tb->tc_ptr);
    } else {
        /* jmp_target was already filled, add enter_sieve now */
        ind_patch_sieve(env, cgc, prev_tb->ind_enter_sieve);
    }
}
#endif

int prolog_count = 0;

volatile sig_atomic_t exit_request;

#if 0
int cpu_exec(CPUX86State *env)
{
    CPUState *cpu = ENV_GET_CPU(env);
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int ret, interrupt_request;
    TranslationBlock *tb;
    uint8_t *tc_ptr;
    tcg_target_ulong next_tb;

    env->tb_tag = 0;
#ifdef RETRANS_IND
    env->has_ind = false;
#endif

    if (cpu->halted) {
        if (!cpu_has_work(cpu)) {
            return EXCP_HALTED;
        }

        cpu->halted = 0;
    }

    current_cpu = cpu;

    /* As long as current_cpu is null, up to the assignment just above,
     * requests by other threads to exit the execution loop are expected to
     * be issued using the exit_request global. We must make sure that our
     * evaluation of the global value is performed past the current_cpu
     * value transition point, which requires a memory barrier as well as
     * an instruction scheduling constraint on modern architectures.  */
    smp_mb();

    if (unlikely(exit_request)) {
        cpu->exit_request = 1;
    }

    /* put eflags in CPU temporary format */
    CC_SRC = env->eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    env->df = 1 - (2 * ((env->eflags >> 10) & 1));
    CC_OP = CC_OP_EFLAGS;
    env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    env->exception_index = -1;

    /* prepare setjmp context for exception handling */
    for(;;) {
        if (sigsetjmp(env->jmp_env, 0) == 0) {
            /* if an exception is pending, we execute it here */
            if (env->exception_index >= 0) {
                if (env->exception_index >= EXCP_INTERRUPT) {
                    /* exit request from the cpu execution loop */
                    ret = env->exception_index;
                    if (ret == EXCP_DEBUG) {
                        cpu_handle_debug_exception(env);
                    }
                    break;
                } else {
                    /* if user mode only, we simulate a fake exception
                       which will be handled outside the cpu execution
                       loop */
                    cc->do_interrupt(cpu);
                    ret = env->exception_index;
                    break;
                }
            }

            next_tb = 0; /* force lookup of first TB */
            for(;;) {
                prolog_count++;

                interrupt_request = cpu->interrupt_request;
                if (unlikely(interrupt_request)) {
                    if (unlikely(cpu->singlestep_enabled & SSTEP_NOIRQ)) {
                        /* Mask out external interrupts for this step. */
                        interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
                    }
                    if (interrupt_request & CPU_INTERRUPT_DEBUG) {
                        cpu->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
                        env->exception_index = EXCP_DEBUG;
                        cpu_loop_exit(env);
                    }
#if defined(TARGET_I386)
#if !defined(CONFIG_USER_ONLY)
                    if (interrupt_request & CPU_INTERRUPT_POLL) {
                        cpu->interrupt_request &= ~CPU_INTERRUPT_POLL;
                        apic_poll_irq(env->apic_state);
                    }
#endif
                    if (interrupt_request & CPU_INTERRUPT_INIT) {
                            cpu_svm_check_intercept_param(env, SVM_EXIT_INIT,
                                                          0);
                            do_cpu_init(x86_env_get_cpu(env));
                            env->exception_index = EXCP_HALTED;
                            cpu_loop_exit(env);
                    } else if (interrupt_request & CPU_INTERRUPT_SIPI) {
                            do_cpu_sipi(x86_env_get_cpu(env));
                    } else if (env->hflags2 & HF2_GIF_MASK) {
                        if ((interrupt_request & CPU_INTERRUPT_SMI) &&
                            !(env->hflags & HF_SMM_MASK)) {
                            cpu_svm_check_intercept_param(env, SVM_EXIT_SMI,
                                                          0);
                            cpu->interrupt_request &= ~CPU_INTERRUPT_SMI;
                            do_smm_enter(x86_env_get_cpu(env));
                            next_tb = 0;
                        } else if ((interrupt_request & CPU_INTERRUPT_NMI) &&
                                   !(env->hflags2 & HF2_NMI_MASK)) {
                            cpu->interrupt_request &= ~CPU_INTERRUPT_NMI;
                            env->hflags2 |= HF2_NMI_MASK;
                            do_interrupt_x86_hardirq(env, EXCP02_NMI, 1);
                            next_tb = 0;
                        } else if (interrupt_request & CPU_INTERRUPT_MCE) {
                            cpu->interrupt_request &= ~CPU_INTERRUPT_MCE;
                            do_interrupt_x86_hardirq(env, EXCP12_MCHK, 0);
                            next_tb = 0;
                        } else if ((interrupt_request & CPU_INTERRUPT_HARD) &&
                                   (((env->hflags2 & HF2_VINTR_MASK) && 
                                     (env->hflags2 & HF2_HIF_MASK)) ||
                                    (!(env->hflags2 & HF2_VINTR_MASK) && 
                                     (env->eflags & IF_MASK && 
                                      !(env->hflags & HF_INHIBIT_IRQ_MASK))))) {
                            int intno;
                            cpu_svm_check_intercept_param(env, SVM_EXIT_INTR,
                                                          0);
                            cpu->interrupt_request &= ~(CPU_INTERRUPT_HARD |
                                                        CPU_INTERRUPT_VIRQ);
                            intno = cpu_get_pic_interrupt(env);
                            qemu_log_mask(CPU_LOG_TB_IN_ASM, "Servicing hardware INT=0x%02x\n", intno);
                            do_interrupt_x86_hardirq(env, intno, 1);
                            /* ensure that no TB jump will be modified as
                               the program flow was changed */
                            next_tb = 0;
#if !defined(CONFIG_USER_ONLY)
                        } else if ((interrupt_request & CPU_INTERRUPT_VIRQ) &&
                                   (env->eflags & IF_MASK) && 
                                   !(env->hflags & HF_INHIBIT_IRQ_MASK)) {
                            int intno;
                            /* FIXME: this should respect TPR */
                            cpu_svm_check_intercept_param(env, SVM_EXIT_VINTR,
                                                          0);
                            intno = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.int_vector));
                            qemu_log_mask(CPU_LOG_TB_IN_ASM, "Servicing virtual hardware INT=0x%02x\n", intno);
                            do_interrupt_x86_hardirq(env, intno, 1);
                            cpu->interrupt_request &= ~CPU_INTERRUPT_VIRQ;
                            next_tb = 0;
#endif
                        }
                    }
#endif
                   /* Don't use the cached interrupt_request value,
                      do_interrupt may have updated the EXITTB flag. */
                    if (cpu->interrupt_request & CPU_INTERRUPT_EXITTB) {
                        cpu->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
                        /* ensure that no TB jump will be modified as
                           the program flow was changed */
                        next_tb = 0;
                    }
                }
                if (unlikely(cpu->exit_request)) {
                    cpu->exit_request = 0;
                    env->exception_index = EXCP_INTERRUPT;
                    cpu_loop_exit(env);
                }
#if defined(DEBUG_DISAS)
                if (qemu_loglevel_mask(CPU_LOG_TB_CPU)) {
                    /* restore flags in standard format */
                    log_cpu_state(cpu, CPU_DUMP_CCOP);
                }
#endif /* DEBUG_DISAS */
                spin_lock(&tcg_ctx.tb_ctx.tb_lock);
                
                next_tb = get_next_tb(env, env->eip, (TranslationBlock *)next_tb);

                if (env->ind_type != NOT_IND) {
                    /* from {ret, ind_jmp, ind_call} */
                    if(next_tb == 0) {
                        /*from sieve */
                        add_sieve_entry(env, tb, env->ind_type);
                        env->ind_type = NOT_IND;
                    } else {
                        if (env->ind_type == TYPE_SYSCALL) {
                            next_tb = 0;
                        } else {
#ifdef IND_OPT
                            patch_ind_opt(env, (TranslationBlock *)next_tb, tb);
                            next_tb = 0;
#endif
                        }
                    }
                }

                if (qemu_loglevel_mask(CPU_LOG_EXEC)) {
                    qemu_log("Trace %p [" TARGET_FMT_lx "] %s\n",
                             tb->tc_ptr, tb->pc, lookup_symbol(tb->pc));
                }
                /* see if we can patch the calling TB. When the TB
                   spans two pages, we cannot safely do a direct
                   jump. */
                if (next_tb != 0 && (uint32_t)tb != next_tb) {
                    tb_add_jump((TranslationBlock *)(next_tb),
                                env->patch_num, tb);
                }
#ifdef RETRANS_IND
                if (env->has_ind == true) {
                    chg_tbs_tag((TranslationBlock *)(env->ind_tb, NORMAL_TB_TAG));
                    env->has_ind = false;
                }
#endif

                spin_unlock(&tcg_ctx.tb_ctx.tb_lock);

                /* cpu_interrupt might be called while translating the
                   TB, but before it is linked into a potentially
                   infinite loop and becomes env->current_tb. Avoid
                   starting execution if there is a pending interrupt. */
                cpu->current_tb = tb;
                barrier();
                if (likely(!cpu->exit_request)) {

                    tc_ptr = tb->tc_ptr;
                    env->target_tc = (uint32_t)tc_ptr;
                    env->ret_tb = 0;
                    env->trapnr = -1;
                    env->ind_type = NOT_IND;

                    /* execute the generated code */
                    next_tb = cpu_tb_exec(cpu, tc_ptr);
                    switch (next_tb & TB_EXIT_MASK) {
                    case TB_EXIT_REQUESTED:
                        /* Something asked us to stop executing
                         * chained TBs; just continue round the main
                         * loop. Whatever requested the exit will also
                         * have set something else (eg exit_request or
                         * interrupt_request) which we will handle
                         * next time around the loop.
                         */
                        tb = (TranslationBlock *)(next_tb & ~TB_EXIT_MASK);
                        next_tb = 0;
                        break;
                    case TB_EXIT_ICOUNT_EXPIRED:
                    {
                        /* Instruction counter expired.  */
                        int insns_left;
                        tb = (TranslationBlock *)(next_tb & ~TB_EXIT_MASK);
                        insns_left = env->icount_decr.u32;
                        if (env->icount_extra && insns_left >= 0) {
                            /* Refill decrementer and continue execution.  */
                            env->icount_extra += insns_left;
                            if (env->icount_extra > 0xffff) {
                                insns_left = 0xffff;
                            } else {
                                insns_left = env->icount_extra;
                            }
                            env->icount_extra -= insns_left;
                            env->icount_decr.u16.low = insns_left;
                        } else {
                            if (insns_left > 0) {
                                /* Execute remaining instructions.  */
                                cpu_exec_nocache(env, insns_left, tb);
                            }
                            env->exception_index = EXCP_INTERRUPT;
                            next_tb = 0;
                            cpu_loop_exit(env);
                        }
                        break;
                    }
                    default:
                        break;
                    }
                }
                cpu->current_tb = NULL;
                /* reset soft MMU for next block (it can currently
                   only be set by a memory fault) */
            } /* for(;;) */
        } else {
            /* Reload env after longjmp - the compiler may have smashed all
             * local variables as longjmp is marked 'noreturn'. */
            cpu = current_cpu;
            env = cpu->env_ptr;
        }
    } /* for(;;) */


    /* restore flags in standard format */
    env->eflags = env->eflags | cpu_cc_compute_all(env, CC_OP)
        | (env->df & DF_MASK);

    /* fail safe : never use current_cpu outside cpu_exec() */
    current_cpu = NULL;
    return ret;
}
#endif

int cpu_exec(CPUX86State *env)
{
    int ret;
    TranslationBlock *tb;
    uint8_t *tc_ptr;
    uint32_t prev_tb;
    int new_tb_count;
    TCGContext *cgc = &tcg_ctx;

    cgc->tb_tag = 0;
    prev_tb = 0; /* force lookup of first TB */
    new_tb_count = -500;

#ifdef RETRANS_IND
    env->has_ind = false;
#endif

    for(;;) {
        prolog_count++;

        tb = get_next_tb(env, env->eip, (TranslationBlock *)prev_tb);

        if(env->ind_type != NOT_IND) {
            /* from {ret, ind_jmp, ind_call} */
            if(prev_tb == 0) {
				/* from sieve */
				add_sieve_entry(cgc, tb, env->ind_type);
				env->ind_type = NOT_IND;
            } else {
                if (env->ind_type == TYPE_SYSCALL) {
                    prev_tb = 0;
                } else {
#ifdef IND_OPT
                    patch_ind_opt(env, cgc, (TranslationBlock *)prev_tb, tb);
                    prev_tb = 0;
#endif
                }
            }
        }

#ifdef CONFIG_DEBUG_EXEC
        qemu_log_mask(CPU_LOG_EXEC, "Trace 0x%08lx [" TARGET_FMT_lx "] %s\n",
                     (long)tb->tc_ptr, tb->pc,
                     lookup_symbol(tb->pc));
#endif

        /* link tb */
        if(prev_tb != 0 && (uint32_t)tb != prev_tb) {
            tb_add_jump((TranslationBlock *)prev_tb, cgc->patch_num, tb);
        }

#ifdef RETRANS_IND
        if(env->has_ind == true) {
            chg_tbs_tag((TranslationBlock *)(env->ind_tb), NORMAL_TB_TAG);
            env->has_ind = false;
        }
#endif

        /* clear env */
        tc_ptr = tb->tc_ptr;
        env->target_tc = (uint32_t)tc_ptr;
        env->ret_tb = 0;
        env->trapnr = -1;
        env->ind_type = NOT_IND;
       
        /* enter code cache */
#if 0
        fprintf(stderr, "tp->pc is %x \n", tb->pc); 
        if (tb->pc == 0x8052b00) {
            fprintf(stderr, "bingo!!!\n");
        }
#endif

        prev_tb = tcg_qemu_tb_exec(tc_ptr);
        
        if (env->ind_type == TYPE_SYSCALL) {
            //fprintf(stderr, "env->trapnr is %d\n", env->trapnr);
            handle_syscall(env, env->trapnr); 
        }

        //fprintf(stderr, "prev_tb = 0x%x pc = 0x%x\n", prev_tb, env->eip);

        //env->current_tb = NULL;
    } /* for(;;) */

    return ret;
}

