/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#include "qemu.h"
#include "qemu-common.h"
#include "qemu/cache-utils.h"
#include "cpu.h"
#include "tcg.h"
#include "qemu/timer.h"
#include "qemu/envlist.h"
#include "elf.h"

char *exec_path;

int singlestep;
const char *filename;
const char *argv0;
int gdbstub_port;
envlist_t *envlist;
const char *cpu_model;
unsigned long mmap_min_addr;
#if defined(CONFIG_USE_GUEST_BASE)
unsigned long guest_base;
int have_guest_base;
#if (TARGET_LONG_BITS == 32) && (HOST_LONG_BITS == 64)
/*
 * When running 32-on-64 we should make sure we can fit all of the possible
 * guest address space into a contiguous chunk of virtual host memory.
 *
 * This way we will never overlap with our own libraries or binaries or stack
 * or anything else that QEMU maps.
 */
# ifdef TARGET_MIPS
/* MIPS only supports 31 bits of virtual address space for user space */
unsigned long reserved_va = 0x77000000;
# else
unsigned long reserved_va = 0xf7000000;
# endif
#else
unsigned long reserved_va;
#endif
#endif

static void usage(void);

static const char *interp_prefix = CONFIG_QEMU_INTERP_PREFIX;
const char *qemu_uname_release = CONFIG_UNAME_RELEASE;

/* XXX: on x86 MAP_GROWSDOWN only works if ESP <= address + 32, so
   we allocate a bigger stack. Need a better solution, for example
   by remapping the process stack directly at the right place */
unsigned long guest_stack_size = 8 * 1024 * 1024UL;

void gemu_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

#if defined(TARGET_I386)
int cpu_get_pic_interrupt(CPUX86State *env)
{
    return -1;
}
#endif

/***********************************************************/
/* Helper routines for implementing atomic operations.  */

/* To implement exclusive operations we force all cpus to syncronise.
   We don't require a full sync, only that no cpus are executing guest code.
   The alternative is to map target atomic ops onto host equivalents,
   which requires quite a lot of per host/target work.  */
static pthread_mutex_t cpu_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t exclusive_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t exclusive_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t exclusive_resume = PTHREAD_COND_INITIALIZER;
static int pending_cpus;

/* Make sure everything is in a consistent state for calling fork().  */
void fork_start(void)
{
    pthread_mutex_lock(&tcg_ctx.tb_ctx.tb_lock);
    pthread_mutex_lock(&exclusive_lock);
    mmap_fork_start();
}

void fork_end(int child)
{
    mmap_fork_end(child);
    if (child) {
        /* Child processes created by fork() only have a single thread.
           Discard information about the parent threads.  */
        first_cpu = thread_cpu;
        first_cpu->next_cpu = NULL;
        pending_cpus = 0;
        pthread_mutex_init(&exclusive_lock, NULL);
        pthread_mutex_init(&cpu_list_mutex, NULL);
        pthread_cond_init(&exclusive_cond, NULL);
        pthread_cond_init(&exclusive_resume, NULL);
        pthread_mutex_init(&tcg_ctx.tb_ctx.tb_lock, NULL);
        gdbserver_fork((CPUArchState *)thread_cpu->env_ptr);
    } else {
        pthread_mutex_unlock(&exclusive_lock);
        pthread_mutex_unlock(&tcg_ctx.tb_ctx.tb_lock);
    }
}

/* Wait for pending exclusive operations to complete.  The exclusive lock
   must be held.  */
static inline void exclusive_idle(void)
{
    while (pending_cpus) {
        pthread_cond_wait(&exclusive_resume, &exclusive_lock);
    }
}

/* Start an exclusive operation.
   Must only be called from outside cpu_arm_exec.   */
static inline void start_exclusive(void)
{
    CPUState *other_cpu;

    pthread_mutex_lock(&exclusive_lock);
    exclusive_idle();

    pending_cpus = 1;
    /* Make all other cpus stop executing.  */
    for (other_cpu = first_cpu; other_cpu; other_cpu = other_cpu->next_cpu) {
        if (other_cpu->running) {
            pending_cpus++;
            cpu_exit(other_cpu);
        }
    }
    if (pending_cpus > 1) {
        pthread_cond_wait(&exclusive_cond, &exclusive_lock);
    }
}

/* Finish an exclusive operation.  */
static inline void end_exclusive(void)
{
    pending_cpus = 0;
    pthread_cond_broadcast(&exclusive_resume);
    pthread_mutex_unlock(&exclusive_lock);
}

/* Wait for exclusive ops to finish, and begin cpu execution.  */
static inline void cpu_exec_start(CPUState *cpu)
{
    pthread_mutex_lock(&exclusive_lock);
    exclusive_idle();
    cpu->running = true;
    pthread_mutex_unlock(&exclusive_lock);
}

/* Mark cpu as not executing, and release pending exclusive ops.  */
static inline void cpu_exec_end(CPUState *cpu)
{
    pthread_mutex_lock(&exclusive_lock);
    cpu->running = false;
    if (pending_cpus > 1) {
        pending_cpus--;
        if (pending_cpus == 1) {
            pthread_cond_signal(&exclusive_cond);
        }
    }
    exclusive_idle();
    pthread_mutex_unlock(&exclusive_lock);
}

void cpu_list_lock(void)
{
    pthread_mutex_lock(&cpu_list_mutex);
}

void cpu_list_unlock(void)
{
    pthread_mutex_unlock(&cpu_list_mutex);
}


#ifdef TARGET_I386
/***********************************************************/
/* CPUX86 core interface */

void cpu_smm_update(CPUX86State *env)
{
}

uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_real_ticks();
}

static void write_dt(void *ptr, unsigned long addr, unsigned long limit,
                     int flags)
{
    unsigned int e1, e2;
    uint32_t *p;
    e1 = (addr << 16) | (limit & 0xffff);
    e2 = ((addr >> 16) & 0xff) | (addr & 0xff000000) | (limit & 0x000f0000);
    e2 |= flags;
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

static uint64_t *idt_table;
#ifdef TARGET_X86_64
static void set_gate64(void *ptr, unsigned int type, unsigned int dpl,
                       uint64_t addr, unsigned int sel)
{
    uint32_t *p, e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
    p[2] = tswap32(addr >> 32);
    p[3] = 0;
}
/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl)
{
    set_gate64(idt_table + n * 2, 0, dpl, 0, 0);
}
#else
static void set_gate(void *ptr, unsigned int type, unsigned int dpl,
                     uint32_t addr, unsigned int sel)
{
    uint32_t *p, e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl)
{
    set_gate(idt_table + n, 0, dpl, 0, 0);
}
#endif

void cpu_loop(CPUX86State *env)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));
    int trapnr;
    abi_ulong pc;
    target_siginfo_t info;

    for(;;) {
        trapnr = cpu_x86_exec(env);
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
                                          env->regs[R_EBP],
                                          0, 0);
            break;
#ifndef TARGET_ABI32
        case EXCP_SYSCALL:
            /* linux syscall from syscall instruction */
            env->regs[R_EAX] = do_syscall(env,
                                          env->regs[R_EAX],
                                          env->regs[R_EDI],
                                          env->regs[R_ESI],
                                          env->regs[R_EDX],
                                          env->regs[10],
                                          env->regs[8],
                                          env->regs[9],
                                          0, 0);
            env->eip = env->exception_next_eip;
            break;
#endif
        case EXCP0B_NOSEG:
        case EXCP0C_STACK:
            info.si_signo = SIGBUS;
            info.si_errno = 0;
            info.si_code = TARGET_SI_KERNEL;
            info._sifields._sigfault._addr = 0;
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP0D_GPF:
            /* XXX: potential problem if ABI32 */
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_fault(env);
            } else
#endif
            {
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SI_KERNEL;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP0E_PAGE:
            info.si_signo = SIGSEGV;
            info.si_errno = 0;
            if (!(env->error_code & 1))
                info.si_code = TARGET_SEGV_MAPERR;
            else
                info.si_code = TARGET_SEGV_ACCERR;
            info._sifields._sigfault._addr = env->cr[2];
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP00_DIVZ:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                /* division by zero */
                info.si_signo = SIGFPE;
                info.si_errno = 0;
                info.si_code = TARGET_FPE_INTDIV;
                info._sifields._sigfault._addr = env->eip;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP01_DB:
        case EXCP03_INT3:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                info.si_signo = SIGTRAP;
                info.si_errno = 0;
                if (trapnr == EXCP01_DB) {
                    info.si_code = TARGET_TRAP_BRKPT;
                    info._sifields._sigfault._addr = env->eip;
                } else {
                    info.si_code = TARGET_SI_KERNEL;
                    info._sifields._sigfault._addr = 0;
                }
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP04_INTO:
        case EXCP05_BOUND:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SI_KERNEL;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP06_ILLOP:
            info.si_signo = SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPN;
            info._sifields._sigfault._addr = env->eip;
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, &info);
                  }
            }
            break;
        default:
            pc = env->segs[R_CS].base + env->eip;
            fprintf(stderr, "qemu: 0x%08lx: unhandled CPU exception 0x%x - aborting\n",
                    (long)pc, trapnr);
            abort();
        }
        process_pending_signals(env);
    }
}
#endif


THREAD CPUState *thread_cpu;

void task_settid(TaskState *ts)
{
    if (ts->ts_tid == 0) {
        ts->ts_tid = (pid_t)syscall(SYS_gettid);
    }
}

void stop_all_tasks(void)
{
    /*
     * We trust that when using NPTL, start_exclusive()
     * handles thread stopping correctly.
     */
    start_exclusive();
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
    int i;
 
    ts->used = 1;
    ts->first_free = ts->sigqueue_table;
    for (i = 0; i < MAX_SIGQUEUE_SIZE - 1; i++) {
        ts->sigqueue_table[i].next = &ts->sigqueue_table[i + 1];
    }
    ts->sigqueue_table[i].next = NULL;
}

static void handle_arg_help(const char *arg)
{
    usage();
}

static void handle_arg_log(const char *arg)
{
    int mask;

    mask = qemu_str_to_log_mask(arg);
    if (!mask) {
        qemu_print_log_usage(stdout);
        exit(1);
    }
    qemu_set_log(mask);
}

static void handle_arg_log_filename(const char *arg)
{
    qemu_set_log_filename(arg);
}

static void handle_arg_set_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_setenv(envlist, token) != 0) {
            usage();
        }
    }
    free(r);
}

static void handle_arg_unset_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_unsetenv(envlist, token) != 0) {
            usage();
        }
    }
    free(r);
}

static void handle_arg_argv0(const char *arg)
{
    argv0 = strdup(arg);
}

static void handle_arg_stack_size(const char *arg)
{
    char *p;
    guest_stack_size = strtoul(arg, &p, 0);
    if (guest_stack_size == 0) {
        usage();
    }

    if (*p == 'M') {
        guest_stack_size *= 1024 * 1024;
    } else if (*p == 'k' || *p == 'K') {
        guest_stack_size *= 1024;
    }
}

static void handle_arg_ld_prefix(const char *arg)
{
    interp_prefix = strdup(arg);
}

static void handle_arg_pagesize(const char *arg)
{
    qemu_host_page_size = atoi(arg);
    if (qemu_host_page_size == 0 ||
        (qemu_host_page_size & (qemu_host_page_size - 1)) != 0) {
        fprintf(stderr, "page size must be a power of two\n");
        exit(1);
    }
}

static void handle_arg_gdb(const char *arg)
{
    gdbstub_port = atoi(arg);
}

static void handle_arg_uname(const char *arg)
{
    qemu_uname_release = strdup(arg);
}

static void handle_arg_cpu(const char *arg)
{
    cpu_model = strdup(arg);
    if (cpu_model == NULL || is_help_option(cpu_model)) {
        /* XXX: implement xxx_cpu_list for targets that still miss it */
#if defined(cpu_list)
        cpu_list(stdout, &fprintf);
#endif
        exit(1);
    }
}

#if defined(CONFIG_USE_GUEST_BASE)
static void handle_arg_guest_base(const char *arg)
{
    guest_base = strtol(arg, NULL, 0);
    have_guest_base = 1;
}

static void handle_arg_reserved_va(const char *arg)
{
    char *p;
    int shift = 0;
    reserved_va = strtoul(arg, &p, 0);
    switch (*p) {
    case 'k':
    case 'K':
        shift = 10;
        break;
    case 'M':
        shift = 20;
        break;
    case 'G':
        shift = 30;
        break;
    }
    if (shift) {
        unsigned long unshifted = reserved_va;
        p++;
        reserved_va <<= shift;
        if (((reserved_va >> shift) != unshifted)
#if HOST_LONG_BITS > TARGET_VIRT_ADDR_SPACE_BITS
            || (reserved_va > (1ul << TARGET_VIRT_ADDR_SPACE_BITS))
#endif
            ) {
            fprintf(stderr, "Reserved virtual address too big\n");
            exit(1);
        }
    }
    if (*p) {
        fprintf(stderr, "Unrecognised -R size suffix '%s'\n", p);
        exit(1);
    }
}
#endif

static void handle_arg_singlestep(const char *arg)
{
    singlestep = 1;
}

static void handle_arg_strace(const char *arg)
{
    do_strace = 1;
}

static void handle_arg_version(const char *arg)
{
    printf("qemu-" TARGET_NAME " version " QEMU_VERSION QEMU_PKGVERSION
           ", Copyright (c) 2003-2008 Fabrice Bellard\n");
    exit(0);
}

struct qemu_argument {
    const char *argv;
    const char *env;
    bool has_arg;
    void (*handle_opt)(const char *arg);
    const char *example;
    const char *help;
};

static const struct qemu_argument arg_table[] = {
    {"h",          "",                 false, handle_arg_help,
     "",           "print this help"},
    {"g",          "QEMU_GDB",         true,  handle_arg_gdb,
     "port",       "wait gdb connection to 'port'"},
    {"L",          "QEMU_LD_PREFIX",   true,  handle_arg_ld_prefix,
     "path",       "set the elf interpreter prefix to 'path'"},
    {"s",          "QEMU_STACK_SIZE",  true,  handle_arg_stack_size,
     "size",       "set the stack size to 'size' bytes"},
    {"cpu",        "QEMU_CPU",         true,  handle_arg_cpu,
     "model",      "select CPU (-cpu help for list)"},
    {"E",          "QEMU_SET_ENV",     true,  handle_arg_set_env,
     "var=value",  "sets targets environment variable (see below)"},
    {"U",          "QEMU_UNSET_ENV",   true,  handle_arg_unset_env,
     "var",        "unsets targets environment variable (see below)"},
    {"0",          "QEMU_ARGV0",       true,  handle_arg_argv0,
     "argv0",      "forces target process argv[0] to be 'argv0'"},
    {"r",          "QEMU_UNAME",       true,  handle_arg_uname,
     "uname",      "set qemu uname release string to 'uname'"},
#if defined(CONFIG_USE_GUEST_BASE)
    {"B",          "QEMU_GUEST_BASE",  true,  handle_arg_guest_base,
     "address",    "set guest_base address to 'address'"},
    {"R",          "QEMU_RESERVED_VA", true,  handle_arg_reserved_va,
     "size",       "reserve 'size' bytes for guest virtual address space"},
#endif
    {"d",          "QEMU_LOG",         true,  handle_arg_log,
     "item[,...]", "enable logging of specified items "
     "(use '-d help' for a list of items)"},
    {"D",          "QEMU_LOG_FILENAME", true, handle_arg_log_filename,
     "logfile",     "write logs to 'logfile' (default stderr)"},
    {"p",          "QEMU_PAGESIZE",    true,  handle_arg_pagesize,
     "pagesize",   "set the host page size to 'pagesize'"},
    {"singlestep", "QEMU_SINGLESTEP",  false, handle_arg_singlestep,
     "",           "run in singlestep mode"},
    {"strace",     "QEMU_STRACE",      false, handle_arg_strace,
     "",           "log system calls"},
    {"version",    "QEMU_VERSION",     false, handle_arg_version,
     "",           "display version information and exit"},
    {NULL, NULL, false, NULL, NULL, NULL}
};

static void usage(void)
{
    const struct qemu_argument *arginfo;
    int maxarglen;
    int maxenvlen;

    printf("usage: qemu-" TARGET_NAME " [options] program [arguments...]\n"
           "Linux CPU emulator (compiled for " TARGET_NAME " emulation)\n"
           "\n"
           "Options and associated environment variables:\n"
           "\n");

    /* Calculate column widths. We must always have at least enough space
     * for the column header.
     */
    maxarglen = strlen("Argument");
    maxenvlen = strlen("Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        int arglen = strlen(arginfo->argv);
        if (arginfo->has_arg) {
            arglen += strlen(arginfo->example) + 1;
        }
        if (strlen(arginfo->env) > maxenvlen) {
            maxenvlen = strlen(arginfo->env);
        }
        if (arglen > maxarglen) {
            maxarglen = arglen;
        }
    }

    printf("%-*s %-*s Description\n", maxarglen+1, "Argument",
            maxenvlen, "Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->has_arg) {
            printf("-%s %-*s %-*s %s\n", arginfo->argv,
                   (int)(maxarglen - strlen(arginfo->argv) - 1),
                   arginfo->example, maxenvlen, arginfo->env, arginfo->help);
        } else {
            printf("-%-*s %-*s %s\n", maxarglen, arginfo->argv,
                    maxenvlen, arginfo->env,
                    arginfo->help);
        }
    }

    printf("\n"
           "Defaults:\n"
           "QEMU_LD_PREFIX  = %s\n"
           "QEMU_STACK_SIZE = %ld byte\n",
           interp_prefix,
           guest_stack_size);

    printf("\n"
           "You can use -E and -U options or the QEMU_SET_ENV and\n"
           "QEMU_UNSET_ENV environment variables to set and unset\n"
           "environment variables for the target process.\n"
           "It is possible to provide several variables by separating them\n"
           "by commas in getsubopt(3) style. Additionally it is possible to\n"
           "provide the -E and -U options multiple times.\n"
           "The following lines are equivalent:\n"
           "    -E var1=val2 -E var2=val2 -U LD_PRELOAD -U LD_DEBUG\n"
           "    -E var1=val2,var2=val2 -U LD_PRELOAD,LD_DEBUG\n"
           "    QEMU_SET_ENV=var1=val2,var2=val2 QEMU_UNSET_ENV=LD_PRELOAD,LD_DEBUG\n"
           "Note that if you provide several changes to a single variable\n"
           "the last change will stay in effect.\n");

    exit(1);
}

static int parse_args(int argc, char **argv)
{
    const char *r;
    int optind;
    const struct qemu_argument *arginfo;

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->env == NULL) {
            continue;
        }

        r = getenv(arginfo->env);
        if (r != NULL) {
            arginfo->handle_opt(r);
        }
    }

    optind = 1;
    for (;;) {
        if (optind >= argc) {
            break;
        }
        r = argv[optind];
        if (r[0] != '-') {
            break;
        }
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        }

        for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
            if (!strcmp(r, arginfo->argv)) {
                if (arginfo->has_arg) {
                    if (optind >= argc) {
                        usage();
                    }
                    arginfo->handle_opt(argv[optind]);
                    optind++;
                } else {
                    arginfo->handle_opt(NULL);
                }
                break;
            }
        }

        /* no option matched the current argv */
        if (arginfo->handle_opt == NULL) {
            usage();
        }
    }

    if (optind >= argc) {
        usage();
    }

    filename = argv[optind];
    exec_path = argv[optind];

    return optind;
}

int main(int argc, char **argv, char **envp)
{
    struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct linux_binprm bprm;
    TaskState *ts;
    CPUArchState *env;
    CPUState *cpu;
    int optind;
    char **target_environ, **wrk;
    char **target_argv;
    int target_argc;
    int i;
    int ret;

    module_call_init(MODULE_INIT_QOM);

    qemu_cache_utils_init(envp);

    if ((envlist = envlist_create()) == NULL) {
        (void) fprintf(stderr, "Unable to allocate envlist\n");
        exit(1);
    }

    /* add current environment into the list */
    for (wrk = environ; *wrk != NULL; wrk++) {
        (void) envlist_setenv(envlist, *wrk);
    }

    /* Read the stack limit from the kernel.  If it's "unlimited",
       then we can do little else besides use the default.  */
    {
        struct rlimit lim;
        if (getrlimit(RLIMIT_STACK, &lim) == 0
            && lim.rlim_cur != RLIM_INFINITY
            && lim.rlim_cur == (target_long)lim.rlim_cur) {
            guest_stack_size = lim.rlim_cur;
        }
    }

    cpu_model = NULL;
#if defined(cpudef_setup)
    cpudef_setup(); /* parse cpu definitions in target config file (TBD) */
#endif

    optind = parse_args(argc, argv);

    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    memset(&bprm, 0, sizeof (bprm));

    /* Scan interp_prefix dir for replacement files. */
    init_paths(interp_prefix);

    if (cpu_model == NULL) {
        cpu_model = "qemu32";
    }
    tcg_exec_init(0);
    cpu_exec_init_all();
    /* NOTE: we need to init the CPU at this stage to get
       qemu_host_page_size */
    env = cpu_init(cpu_model);
    if (!env) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }
    cpu = ENV_GET_CPU(env);
    cpu_reset(cpu);

    thread_cpu = cpu;

    if (getenv("QEMU_STRACE")) {
        do_strace = 1;
    }

    target_environ = envlist_to_environ(envlist, NULL);
    envlist_free(envlist);

    /*
     * Read in mmap_min_addr kernel parameter.  This value is used
     * When loading the ELF image to determine whether guest_base
     * is needed.  It is also used in mmap_find_vma.
     */
    {
        FILE *fp;

        if ((fp = fopen("/proc/sys/vm/mmap_min_addr", "r")) != NULL) {
            unsigned long tmp;
            if (fscanf(fp, "%lu", &tmp) == 1) {
                mmap_min_addr = tmp;
                qemu_log("host mmap_min_addr=0x%lx\n", mmap_min_addr);
            }
            fclose(fp);
        }
    }

    /*
     * Prepare copy of argv vector for target.
     */
    target_argc = argc - optind;
    target_argv = calloc(target_argc + 1, sizeof (char *));
    if (target_argv == NULL) {
	(void) fprintf(stderr, "Unable to allocate memory for target_argv\n");
	exit(1);
    }

    /*
     * If argv0 is specified (using '-0' switch) we replace
     * argv[0] pointer with the given one.
     */
    i = 0;
    if (argv0 != NULL) {
        target_argv[i++] = strdup(argv0);
    }
    for (; i < target_argc; i++) {
        target_argv[i] = strdup(argv[optind + i]);
    }
    target_argv[target_argc] = NULL;

    ts = g_malloc0 (sizeof(TaskState));
    init_task_state(ts);
    /* build Task State */
    ts->info = info;
    ts->bprm = &bprm;
    env->opaque = ts;
    task_settid(ts);

    ret = loader_exec(filename, target_argv, target_environ, regs,
        info, &bprm);
    if (ret != 0) {
        printf("Error while loading %s: %s\n", filename, strerror(-ret));
        _exit(1);
    }

    for (wrk = target_environ; *wrk; wrk++) {
        free(*wrk);
    }

    free(target_environ);

    if (qemu_log_enabled()) {
        log_page_dump();

        qemu_log("start_brk   0x" TARGET_ABI_FMT_lx "\n", info->start_brk);
        qemu_log("end_code    0x" TARGET_ABI_FMT_lx "\n", info->end_code);
        qemu_log("start_code  0x" TARGET_ABI_FMT_lx "\n",
                 info->start_code);
        qemu_log("start_data  0x" TARGET_ABI_FMT_lx "\n",
                 info->start_data);
        qemu_log("end_data    0x" TARGET_ABI_FMT_lx "\n", info->end_data);
        qemu_log("start_stack 0x" TARGET_ABI_FMT_lx "\n",
                 info->start_stack);
        qemu_log("brk         0x" TARGET_ABI_FMT_lx "\n", info->brk);
        qemu_log("entry       0x" TARGET_ABI_FMT_lx "\n", info->entry);
    }

    target_set_brk(info->brk);
    syscall_init();
    signal_init();

#if defined(CONFIG_USE_GUEST_BASE)
    /* Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
       generating the prologue until now so that the prologue can take
       the real value of GUEST_BASE into account.  */
    tcg_prologue_init(&tcg_ctx);
#endif

#if defined(TARGET_I386)
    cpu_x86_set_cpl(env, 3);

    env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
    env->hflags |= HF_PE_MASK;
    if (env->features[FEAT_1_EDX] & CPUID_SSE) {
        env->cr[4] |= CR4_OSFXSR_MASK;
        env->hflags |= HF_OSFXSR_MASK;
    }
#ifndef TARGET_ABI32
    /* enable 64 bit mode if possible */
    if (!(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM)) {
        fprintf(stderr, "The selected x86 CPU does not support 64 bit mode\n");
        exit(1);
    }
    env->cr[4] |= CR4_PAE_MASK;
    env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
    env->hflags |= HF_LMA_MASK;
#endif

    /* flags setup : we activate the IRQs by default as in user mode */
    env->eflags |= IF_MASK;

    /* linux register setup */
    env->regs[R_EAX] = regs->eax;
    env->regs[R_EBX] = regs->ebx;
    env->regs[R_ECX] = regs->ecx;
    env->regs[R_EDX] = regs->edx;
    env->regs[R_ESI] = regs->esi;
    env->regs[R_EDI] = regs->edi;
    env->regs[R_EBP] = regs->ebp;
    env->regs[R_ESP] = regs->esp;
    env->eip = regs->eip;
    fprintf(stderr, "env->regs[esp] is %x\n", regs->esp);

    /* linux interrupt setup */
#ifndef TARGET_ABI32
    env->idt.limit = 511;
#else
    env->idt.limit = 255;
#endif
    env->idt.base = target_mmap(0, sizeof(uint64_t) * (env->idt.limit + 1),
                                PROT_READ|PROT_WRITE,
                                MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    idt_table = g2h(env->idt.base);
    set_idt(0, 0);
    set_idt(1, 0);
    set_idt(2, 0);
    set_idt(3, 3);
    set_idt(4, 3);
    set_idt(5, 0);
    set_idt(6, 0);
    set_idt(7, 0);
    set_idt(8, 0);
    set_idt(9, 0);
    set_idt(10, 0);
    set_idt(11, 0);
    set_idt(12, 0);
    set_idt(13, 0);
    set_idt(14, 0);
    set_idt(15, 0);
    set_idt(16, 0);
    set_idt(17, 0);
    set_idt(18, 0);
    set_idt(19, 0);
    set_idt(0x80, 3);

    /* linux segment setup */
    {
        uint64_t *gdt_table;
        env->gdt.base = target_mmap(0, sizeof(uint64_t) * TARGET_GDT_ENTRIES,
                                    PROT_READ|PROT_WRITE,
                                    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        env->gdt.limit = sizeof(uint64_t) * TARGET_GDT_ENTRIES - 1;
        gdt_table = g2h(env->gdt.base);
#ifdef TARGET_ABI32
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
#else
        /* 64 bit code segment */
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 DESC_L_MASK |
                 (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
#endif
        write_dt(&gdt_table[__USER_DS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 (3 << DESC_DPL_SHIFT) | (0x2 << DESC_TYPE_SHIFT));
    }
    cpu_x86_load_seg(env, R_CS, __USER_CS);
    cpu_x86_load_seg(env, R_SS, __USER_DS);
#ifdef TARGET_ABI32
    cpu_x86_load_seg(env, R_DS, __USER_DS);
    cpu_x86_load_seg(env, R_ES, __USER_DS);
    cpu_x86_load_seg(env, R_FS, __USER_DS);
    cpu_x86_load_seg(env, R_GS, __USER_DS);
    /* This hack makes Wine work... */
    env->segs[R_FS].selector = 0;
#else
    cpu_x86_load_seg(env, R_DS, 0);
    cpu_x86_load_seg(env, R_ES, 0);
    cpu_x86_load_seg(env, R_FS, 0);
    cpu_x86_load_seg(env, R_GS, 0);
#endif
#endif


    if (gdbstub_port) {
        if (gdbserver_start(gdbstub_port) < 0) {
            fprintf(stderr, "qemu: could not open gdbserver on port %d\n",
                    gdbstub_port);
            exit(1);
        }
        gdb_handlesig(cpu, 0);
    }
    cpu_loop(env);
    /* never exits */
    return 0;
}
