#include "retrans-ind.h"

#ifdef RETRANS_IND

#define BROADEN_TRAVEL
//#define VAR_PATH

static TranslationBlock *retrans_stack[RETRANS_STACK_MAX];
static int32_t retrans_stack_patch[RETRANS_STACK_MAX];
static int32_t retrans_stack_index = 0;

static TranslationBlock *tb_path[PATH_DEPTH_MAX];
static uint32_t tb_path_patch[PATH_DEPTH_MAX];
static uint32_t tb_path_index = 0;

static uint32_t retrans_pcs[RETRANS_STACK_MAX];
static uint32_t retrans_pcs_index = 0;
static uint32_t path_depth;

uint32_t cur_path[PATH_DEPTH_MAX + 1];
bool is_retrans = false;

void chg_tbs_tag(TranslationBlock *tb, int depth)
{
    int i;

#if 0
    //fprintf(stderr, "retrans_again: 0x%x\n", tb->pc);
    tb->tb_tag = RETRANS_TB_TAG;
    if(depth == PATH_DEPTH - 1 || tb->jmp_from_index == 0) return;

    for(i = 0; i < tb->jmp_from_index; i++) {
        tb = tb->jmp_from[0];
        chg_tbs_tag(tb, depth + 1);
    }
#endif
#if 1
    //fprintf(stderr, "retrans:\n");
    for(i = 0; i < PATH_DEPTH; i++) {
        tb->tb_tag = RETRANS_TB_TAG;
        //fprintf(stderr, "0x%x<-", tb->pc);
        if(tb->jmp_from_index == 0) {
            //fprintf(stderr, "||||");
            break;
        }
        tb = tb->jmp_from[0];
    }
    //if(i == PATH_DEPTH) fprintf(stderr, "0x%x<-", tb->pc);
    //fprintf(stderr, "\n");
#endif
}

bool is_tb_retransed(TranslationBlock *tb)
{
    int i;
   
    /* find if this ind_insn was retransed */
    for(i = 0; i < retrans_pcs_index; i++) {
        if(tb->pc == retrans_pcs[i]) break;
    }

    if(i != retrans_pcs_index) {
        return true;
    } else {
        return false;
    }
}

static void regen_target_code(CPUState *env, TranslationBlock *tb)
{
    decode_t ds1, *ds = &ds1;
    int num_insns;
    bool cont_trans;

    ///fprintf(stderr, "regen: tb:0x%x\n", (uint32_t)tb->pc);

    cgc->pc_start = tb->pc;
    cgc->pc_ptr = cgc->pc_start;
    env->code_ptr = tb->tc_ptr;
    cont_trans = true;
    env->patch_count = 0;
    cur_tb = tb;

    SuperTransBlock *cur_stb;
    cur_stb = &(cgc->stbs[cgc->stb_count++]);
    ABORT_IF((cgc->stb_count >= STB_MAX), "stb count, overflow\n");

    cur_stb->pc_start = tb->pc;
    cur_stb->tc_ptr = (uint32_t)(tb->tc_ptr);

    ///printf("start tb_gen_code cgc->pc_ptr = 0x%x\n", cgc->pc_ptr);
    for(num_insns = 0; ;num_insns++) {
        simple_disas_insn(ds, cgc->pc_ptr);
        ///fprintf(stderr, "regen pc_ptr = 0x%x\n", cgc->pc_ptr);
        ABORT_IF((ds->opstate & OPSTATE_ADDR16), "error: OPSTATE_ADDR16\n");

        cgc->insn_len = ds->decode_eip - cgc->pc_ptr;
        cgc->pc_ptr = ds->decode_eip;

        /* emit the insn */
        cont_trans = (ds->emitfn)(env, ds);
        tb->insn_count++;

        /* stop translation if indicated */
        if (cont_trans == false) break;

        if ((env->patch_count >= PATCH_ARRAY_SIZE - 2) ||
            (num_insns >= MAX_INSNS)) {
            if(tb->tc_ptr == env->code_ptr) {
                tb->tc_ptr = (uint8_t *)NOT_TRANS_YET;
            }
            code_emit8(env->code_ptr, 0xe9);
            code_emit32(env->code_ptr, NEED_PATCH_32);
            note_patch(env, env->code_ptr - 4, (uint8_t *)cgc->pc_ptr, 
                       (uint8_t *)tb, tb->func_addr, tb->tb_tag);
            break;
        }
    } /* end for */
    cur_stb->pc_end = cgc->pc_ptr - 1;
    ///qemu_log("end for cgc->pc_ptr = 0x%x\n", cgc->pc_ptr);

    lazy_patch(env);

    cgc->s_code_size += (cgc->pc_ptr - cgc->pc_start);

    code_gen_ptr = env->code_ptr;
    ABORT_IF((code_gen_ptr - code_gen_buffer > DEFAULT_CODE_GEN_BUFFER_SIZE),
           "code_buffer overflow\n");
    tb->hcode_size = code_gen_ptr - tb->tc_ptr;
}


static void tb_set_jmp(TranslationBlock *tb, int n, uint32_t target)
{
    uint32_t jmp_addr;

    jmp_addr = (uint32_t)tb->tc_ptr + tb->tb_jmp_offset[n];
#if 0
    fprintf(stderr, "offset: %d, 0x%x\n", n, tb->tb_jmp_offset[n]);
    fprintf(stderr, "prev_tgt: 0x%x, tgt: 0x%x, prev_off: 0x%x\n",
                     *(uint32_t *)jmp_addr + jmp_addr + 4, target,
                     *(uint32_t *)jmp_addr);
#endif
    *(uint32_t *)jmp_addr = target - (jmp_addr + 4);
}

static void get_path(int pos)
{
    int j;
    int path_idx;
    
    path_idx = 0;
    memset(cur_path, 0, sizeof(cur_path));
    for(j = pos + 1; retrans_stack[j] != NULL ; j++) {
        cur_path[path_idx++] = retrans_stack[j]->pc;
    }

    //fprintf(stderr, "0x%x<-0x%x<-0x%x<-0x%x<-0x%x\n", cur_path[0], 
    //        cur_path[1], cur_path[2], cur_path[3], cur_path[4]);
}

static void retrans_ind_tb(CPUState *env)
{
    int i, j, n;
    int transed_index;
    TranslationBlock *tb, *new_tb, *old_tb;
    TranslationBlock *transed_tbs[PATH_DEPTH_MAX];

    new_tb = NULL;
    transed_index = 0;

#ifdef STATIC_PROF
    get_path(0);
#endif
    for(i = 0; i < retrans_stack_index; i++) {
        tb = retrans_stack[i];
        if(retrans_stack[i+1] == NULL) {
            /* the leaf tb, only modify the jmp insn */
            n = retrans_stack_patch[i];
            tb_set_jmp(tb, n, (uint32_t)new_tb->tc_ptr);
            i++; /* skip the "NULL" slot */
            for(j = 0; j < transed_index; j++) {
                //fprintf(stderr, "tag: %d 0x%x\n", j, transed_tbs[j]->pc);
                transed_tbs[j]->tb_tag = RETRANS_TB_TAG;
            }
            transed_index = 0;
#ifdef STATIC_PROF
            if(i != retrans_stack_index - 1) get_path(i+1);
#endif
        } else {
            /* not leaf, retrans */
            /* modify the tag of exist tb, 
               so that the new_tb will be linked */
            old_tb = tb_find_fast(tb->pc, 0);
            while(old_tb != NULL) {
                old_tb->tb_tag = RETRANS_TB_TAG;
                old_tb = tb_find_fast(tb->pc, 0);
            }
            /* the tb following prev_tb can be transed together with preb_tb */
            if(retrans_stack_patch[i + 1] != CONT_TRANS_TAG) {
                //fprintf(stderr, "retrans_tb: 0x%x \n", tb->pc);
                new_tb = make_tb(env, tb->pc, tb->func_addr, 0);
                new_tb->tc_ptr = code_gen_ptr;
                regen_target_code(env, new_tb);
            } else {
                new_tb = make_tb(env, tb->pc, tb->func_addr, 0);
            }
            transed_tbs[transed_index++] = new_tb;
        }
    }
}

#ifdef BROADEN_TRAVEL
typedef struct retr_node {
    TranslationBlock *tb;
    struct retr_node *next;
    uint32_t patch_num;
    uint32_t depth;
} retr_node;

#define LEAF_MAX	4096
#define NODE_TH		6
uint32_t get_retrans_tb(CPUState *env, TranslationBlock *start_tb)
{
    int i;
    retr_node nodes[PATH_DEPTH * LEAF_MAX];
    retr_node *leaves[LEAF_MAX];
    retr_node *node;
    int node_idx, leaf_idx;
    retr_node *travel_queue[PATH_DEPTH * LEAF_MAX];
    int queue_head, queue_tail;
    TranslationBlock *tb;
    int depth;
    int path_count;

    //fprintf(stderr, "enter get_retrans_tb, tb = 0x%x\n", start_tb->pc);
    path_count = 0;
    node_idx = 0;
    leaf_idx = 0;
    depth = 0; 
    queue_head = 0;
    queue_tail = 0;

    node = &nodes[node_idx++];
    node->tb = start_tb;
    node->depth = 0;
    node->patch_num = CONT_TRANS_TAG;
    node->next = NULL;

#ifdef VAR_PATH
    path_depth = 3;
#else
    path_depth = PATH_DEPTH;
#endif

    /* Broaden First Travel */
    travel_queue[queue_tail++] = node;

    while(queue_head != queue_tail) {
        node = travel_queue[queue_head++];
        tb = node->tb;

#ifdef VAR_PATH
        /* check the node num */
        if(node->depth == path_depth && path_depth < PATH_DEPTH_MAX) {
            if(node_idx < NODE_TH) {
                path_depth++;
            }
	}
#endif

	if(node->depth == path_depth ||
           tb->jmp_from_index == 0) {
    	    //fprintf(stderr, "node pc: %p d=%d\n", node->tb->pc, node->depth);
            leaves[leaf_idx++] = node;
        } else {
            for(i = 0; i < tb->jmp_from_index; i++) {
                if(tb->jmp_from[i] != NULL) {
                    retr_node *child_node;
                    child_node = &nodes[node_idx++];
                    child_node->tb = tb->jmp_from[i];
                    child_node->next = node;
                    child_node->depth = node->depth + 1;
                    child_node->patch_num = tb->jmp_from_num[i];
                    travel_queue[queue_tail++] = child_node;
                } else {
                    //fprintf(stderr, "jmp_from err\n");
                    abort();
                }
            }
        }
    }
    //fprintf(stderr, "%d\n", node_idx);
    ABORT_IF((node_idx > PATH_DEPTH * LEAF_MAX), "retrans node overflow\n");

    /* put the travel result into retrans_stack */
    for(i = 0; i < leaf_idx; i++) {
        int pos;

        node = leaves[i];
        /* remove the unuse leaf */
        while(node != NULL && node->patch_num == CONT_TRANS_TAG)
            node = node->next;
        if(node == NULL) continue;

        path_count++;
	//fprintf(stderr, "depth=%d, index=%d\n", node->depth, retrans_stack_index);
        pos = retrans_stack_index + node->depth;
        retrans_stack_index = pos + 2;
        retrans_stack[pos + 1] = NULL;

	/* push TBs from the leaf */
        while(node->next != NULL) {
            retrans_stack[pos] = node->tb;
            retrans_stack_patch[pos]  = node->patch_num;
	    node = node->next;
            pos--;
        }
        retrans_stack[pos] = node->tb;
    }
    //fprintf(stderr, "exit get_retrans_tb\n");
    return (retrans_stack_index - path_count);
}

void retrans_ind(CPUState *env, TranslationBlock *tb)
{
    retrans_stack_index = 0;
    tb_path_index = 0;
    is_retrans = true;

    //rebuild_profed_tb(env, tb);
    ind_patch_sieve(env, tb->retrans_patch_ptr);

    tb->retransed = true;
    tb->retrans_count = get_retrans_tb(env, tb);

    /* retrans the TBs in the stack */
    retrans_ind_tb(env);
    
    is_retrans = false;

    retrans_pcs[retrans_pcs_index++] = tb->pc;
#if 0
    int i;
    for(i = 0; i < retrans_stack_index; i++) {
       if(retrans_stack[i] != NULL)
           fprintf(stderr, "tb: 0x%x->", retrans_stack[i]->pc);
       else
           fprintf(stderr, "NULL\n");
    }
#endif
}
#endif

void cemit_retrans_ind(CPUX86State *env, uint32_t ind_type)
{
    uint8_t *patch_addr;
    uint32_t addr, jmp_offset;

    cur_tb->ind_miss_count = 0;
    addr = (uint32_t)&cur_tb->ind_miss_count;

    /* pushf */
    code_emit8(env->code_ptr, 0x9c);
    /* incl tb->ind_miss_count */
    code_emit8(env->code_ptr, 0xff);
    code_emit8(env->code_ptr, 0x05); /* ModRM = 00 000 101b */
    code_emit32(env->code_ptr, addr);
    /* cmpl ind_miss_count, RETRANS_THRESHOLD */
    code_emit8(env->code_ptr, 0x81);
    code_emit8(env->code_ptr, 0x3d); /* ModRM = 00 111 101b */
    code_emit32(env->code_ptr, addr);
    code_emit32(env->code_ptr, RETRANS_THRESHOLD);
    /* je equal */
    /* fall-through to the code_ptr */
    code_emit8(env->code_ptr, 0x0f);
    code_emit8(env->code_ptr, 0x84);
    patch_addr = env->code_ptr;
    code_emit32(env->code_ptr, NEED_PATCH_32);
    /* popf */
    code_emit8(env->code_ptr, 0x9d);

    /* equal: NOTE: following code is placed in sieve_code_ptr */
    *(uint32_t *)patch_addr = env->sieve_code_ptr - patch_addr - 4;
    /* pusha */
    code_emit8(env->sieve_code_ptr, 0x60);
    /* push cur_tb */
    code_emit8(env->sieve_code_ptr, 0x68);
    code_emit32(env->sieve_code_ptr, (uint32_t)cur_tb);
    /* push env */
    code_emit8(env->sieve_code_ptr, 0x68);
    code_emit32(env->sieve_code_ptr, (uint32_t)env);
    /* call retrans_ind */
    code_emit8(env->sieve_code_ptr, 0xe8);
    jmp_offset = (uint32_t)retrans_ind - (uint32_t)(env->sieve_code_ptr) - 4;
    code_emit32(env->sieve_code_ptr, jmp_offset);
    /* leal %esp, 8(%esp) */
    code_emit8(env->sieve_code_ptr, 0x8d);
    code_emit8(env->sieve_code_ptr, 0x64); /*01 100 100 */
    code_emit8(env->sieve_code_ptr, 0x24); /*10 100 100 */
    code_emit8(env->sieve_code_ptr, 8);
    /* popa */
    code_emit8(env->sieve_code_ptr, 0x61);
    /* popf */
    code_emit8(env->sieve_code_ptr, 0x9d);
#if 0
    /* pop %ecx */
    code_emit8(env->sieve_code_ptr, 0x59);
    /* mov $cur_tb, (ret_tb) */
    addr = (uint32_t)&(env->ret_tb);
    code_emit8(env->sieve_code_ptr, 0xc7);
    code_emit8(env->sieve_code_ptr, 0x05); /* ModRM = 00 000 101b */
    code_emit32(env->sieve_code_ptr, addr);
    code_emit32(env->sieve_code_ptr, (uint32_t)cur_tb);
    /* mov m_ind_type, (&env->ind_type) */
    addr = (uint32_t)&(env->ind_type);
    code_emit8(env->sieve_code_ptr, 0xc7);
    code_emit8(env->sieve_code_ptr, 0x05); /* ModRM = 00 000 101b */
    code_emit32(env->sieve_code_ptr, addr);
    code_emit32(env->sieve_code_ptr, IND_TYPE_JMP);
    /* pop (env->eip) */
    addr = (uint32_t)&(env->eip);
    code_emit8(env->sieve_code_ptr, 0x8fu);
    code_emit8(env->sieve_code_ptr, 0x05u); /* ModRM = 00 000 101b */
    code_emit32(env->sieve_code_ptr, addr);
    /* jmp tb_epilogue */
    code_emit8(env->sieve_code_ptr, 0xe9u);
    jmp_offset = cgc->tb_ret_addr - env->sieve_code_ptr - 4;
    code_emit32(env->sieve_code_ptr, jmp_offset);
#else
    /* jmp back to code_ptr */
    code_emit8(env->sieve_code_ptr, 0xe9);
    code_emit32(env->sieve_code_ptr,
               (uint32_t)env->code_ptr - (uint32_t)env->sieve_code_ptr - 4);
#endif

    ABORT_IF((env->sieve_code_ptr - sieve_buffer > DEFAULT_SIEVE_BUFFER_SIZE),
           "out of sieve buffer\n");
}

#if 0
//deep travel
void retrans_ind(CPUState *env, TranslationBlock *tb, uint32_t rc_target)
{
    retrans_stack_index = 0;
    tb_path_index = 0;
    is_retrans = true;

#ifdef VAR_PATH
    path_depth = 2;
#else
    path_depth = PATH_DEPTH;
#endif

    //fprintf(stderr, "enter retrans_ind, rc_target: 0x%x\n", rc_target);
    if(rc_target == 0) {
        //qemu_log("retrans jind: 0x%x tc_ptr: %p\n", tb->pc, tb->tc_ptr);
        *(uint8_t *)(tb->retrans_patch_ptr) = JIND_RETRANS_PATCH;
    } else {
        //qemu_log("retrans cind: 0x%x tc_ptr: %p\n", tb->pc, tb->tc_ptr);
        *(uint8_t *)(tb->retrans_patch_ptr) = CIND_RETRANS_PATCH;
    }

    tb->retransed = true;
    tb->retrans_count = get_retrans_tb(env, tb, CONT_TRANS_TAG, 0);

#ifdef VAR_PATH
    if(tb->retrans_count < 5) {
        retrans_stack_index = 0;
        tb_path_index = 0;
        path_depth = path_depth * 2;
        //fprintf(stderr, "retrans_count:%d->", tb->retrans_count);
        tb->retrans_count = get_retrans_tb(env, tb, CONT_TRANS_TAG, 0);
        //fprintf(stderr, "%d\n", tb->retrans_count);
    }
    if(tb->retrans_count < 5) {
        retrans_stack_index = 0;
        tb_path_index = 0;
        path_depth = path_depth * 2;
        //fprintf(stderr, "2retrans_count:%d->", tb->retrans_count);
        tb->retrans_count = get_retrans_tb(env, tb, CONT_TRANS_TAG, 0);
        //fprintf(stderr, "%d\n", tb->retrans_count);
    }
#endif

    /* retrans the TBs in the stack */
    remove_unuse_leaf(env);
    retrans_ind_tb(env);
    
    is_retrans = false;

    retrans_pcs[retrans_pcs_index++] = tb->pc;
#if 0
    int i;
    for(i = 0; i < retrans_stack_index; i++) {
       if(retrans_stack[i] != NULL)
           fprintf(stderr, "tb: 0x%x->", retrans_stack[i]->pc);
       else
           fprintf(stderr, "NULL\n");
    }
#endif
}

uint32_t get_retrans_tb(CPUState *env, TranslationBlock *tb,
                               uint32_t patch_num, uint32_t depth)
{
    uint32_t replic_count;        
    int i;

#if 0
    fprintf(stderr, "jind tb:0x%x pc:0x%x depth: %u index: %u\n",
                    (uint32_t)tb->tc_ptr, tb->pc, depth, tb->jmp_from_index);
    if(tb->jmp_from_index == 0) {
        fprintf(stderr, "leaf tb 0x%x\n", tb->pc);
    }
#endif
    /* recursive stop condition */
    if(tb->jmp_from_index == 0 || depth == path_depth) {
        if(depth !=0) {
            if(retrans_stack_index + tb_path_index + 2 > RETRANS_STACK_MAX) {
                fprintf(stderr, "retrans_max exceeds\n");
                return 0;
            } else {
                /* push previous tbs */
                for(i = 0; i < tb_path_index; i++) {
                    retrans_stack_patch[retrans_stack_index] = tb_path_patch[i];
                    retrans_stack[retrans_stack_index++] = tb_path[i];
                }
                /* push leaf TB */
                retrans_stack_patch[retrans_stack_index] = patch_num;
                retrans_stack[retrans_stack_index++] = tb;
                retrans_stack[retrans_stack_index++] = NULL;
                return 1;
            }
        } else {
            /* jind TB has no fan in */
            //fprintf(stdout, "no fan in: 0x%x\n", tb->pc);
            return 0;
        }
    }

    replic_count = 0;
    /* use global variable tb_path[] to store current path */
    tb_path_patch[tb_path_index] = patch_num;
    tb_path[tb_path_index++] = tb;
    for(i = 0; i < tb->jmp_from_index; i++) {
        if(tb->jmp_from[i] != NULL) {
            replic_count += get_retrans_tb(env, tb->jmp_from[i], 
                                           tb->jmp_from_num[i], depth + 1);
        }
    }
    tb_path_index--;
#if 0
    if(depth == 0) {
        fprintf(stderr, "jind tb: 0x%x, count: %d\n", (uint32_t)tb->pc, replic_count);
    }
#endif
    return replic_count;
}

static void remove_unuse_leaf(CPUState *env)
{
    TranslationBlock *tb;
    int patch;
    int w_pos, pos, last_pos;
    int j;

    w_pos = 0;
    last_pos = 0;
    for(pos = 0; pos < retrans_stack_index; pos++) {
        tb = retrans_stack[pos];
        /* find path boudary */
        if(retrans_stack[pos + 1] == NULL) {
            /* if a leaf tb pass through to the next_tb, it can be removed */
            for(j = pos; j >= 0; j--) {
                patch = retrans_stack_patch[j];
                tb = retrans_stack[j];
                if(patch != CONT_TRANS_TAG || tb == NULL) break;
	    }
            if (last_pos < j) {
	        while (last_pos <= j) {
                    retrans_stack[w_pos] = retrans_stack[last_pos];
                    retrans_stack_patch[w_pos] = retrans_stack_patch[last_pos];
                    w_pos++;
                    last_pos++;
                }
                //fprintf(stderr, "pos:%d, last:%d, w:%d\n", pos, last_pos, w_pos);
                retrans_stack_patch[w_pos] = CONT_TRANS_TAG + 1;
                retrans_stack[w_pos++] = NULL;
            }
	    last_pos = pos + 2;
        }
    }
    retrans_stack_index = w_pos;
}

#endif //end deep travel

#endif

