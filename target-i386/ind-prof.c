#include "ind-prof.h"
#include "retrans-ind.h"

bool prof_run = false;

uint32_t count_ind_tgt(ind_tgt_stat *node, uint32_t tgt)
{
    int idx;

    idx = IND_HASH(tgt);
    if((node->tgt_count[idx])++ == IND_THRESHOLD) {
        return node->tgt_count[idx];
    } else {
        return 0;
    }
}

#define SWAP(x ,y , tmp) \
    do { \
        tmp = x; \
        x = y; \
        y = tmp; \
    } while(0)


static void sort_tgt(stat_node *node)
{
    int i, j;
    int done;
    uint32_t tmp;

    for(i = 0; i < node->tgt_count - 1; i++) {
        done = 1;
        for(j = 0; j < node->tgt_count - i - 1; j++) {
            if(node->tgt_addr_hit[j] < node->tgt_addr_hit[j + 1]) {
                done = 0;
                SWAP(node->tgt_addr_hit[j], node->tgt_addr_hit[j+1], tmp);
                SWAP(node->tgt_addr[j], node->tgt_addr[j+1], tmp);
            }
        }
        if(done == 1) break;
    }
}

void stat_src_add(uint32_t src_addr) 
{
    TCGContext *cgc = &tcg_ctx;
    int i;   

    //fprintf(stderr, "src_add: 0x%x\n", src_addr);
    for(i = 0; i < cgc->stat_node_count; i++) {
        if(cgc->stat_nodes[i].src_addr == src_addr) break;
    }

    if(i == cgc->stat_node_count) {
        cgc->stat_node_count++;
        cgc->stat_nodes[i].src_addr = src_addr;
        cgc->stat_nodes[i].tgt_count = 0;
    }
    
    ABORT_IF((cgc->stat_node_count == STAT_NODE_MAX), "STAT_NODE overflow\n");

}

static void stat_tgt_recent_th(uint32_t tgt_addr, stat_node *node, uint32_t hits)
{
    int i;

    /* check recent */
    for(i = 0; i < IND_SLOT_MAX; i++) {
        if(tgt_addr == node->tgt_recent_addr[i]) {
           node->tgt_recent_hit++;
           break;
        }
    }

    /* add recent */
    if(node->recent_index < IND_SLOT_MAX) {
        if(i == IND_SLOT_MAX) {
	    if(hits > IND_THRESHOLD) {
                //fprintf(stderr, "count: %d\n", hits);
                node->tgt_recent_addr[node->recent_index] = tgt_addr;
                node->recent_index++;
	    }
        }
    }
}

static void stat_tgt_recent_fifo(uint32_t tgt_addr, stat_node *node)
{
    int i;

    /* check recent */
    for(i = 0; i < IND_SLOT_MAX; i++) {
        if(tgt_addr == node->tgt_recent_addr[i]) {
           node->tgt_recent_hit++;
           break;
        }
    }
    /* add recent */
    if(i == IND_SLOT_MAX) {
        node->tgt_recent_addr[node->recent_index] = tgt_addr;
        node->recent_index++;
        if (node->recent_index >= IND_SLOT_MAX)
            node->recent_index -= IND_SLOT_MAX;
    }
}

/* fill the first encounter target to slot */
static void stat_tgt_recent_once(uint32_t tgt_addr, stat_node *node)
{
    int i;

    /* check recent */
    for(i = 0; i < IND_SLOT_MAX; i++) {
        if(tgt_addr == node->tgt_recent_addr[i]) {
           node->tgt_recent_hit++;
           break;
        }
    }

    /* add recent */
    if(i == IND_SLOT_MAX) {
	if(node->recent_index < IND_SLOT_MAX) {
            node->tgt_recent_addr[node->recent_index] = tgt_addr;
            node->recent_index++;
        }
    }
}

#ifdef PROF_PATH
static stat_node *make_stat_node(uint32_t src_addr, uint32_t path[], uint32_t idx)
{
    stat_node *node;

    cgc->stat_node_count++;
    node = &cgc->stat_nodes[idx];
    node->src_addr = src_addr;
    memcpy(node->path, path, sizeof(node->path));
    node->tgt_count = 0;
    node->tgt_recent_hit = 0;

    //fprintf(stderr, "%d\n", cgc->stat_node_count);
    ABORT_IF((cgc->stat_node_count == STAT_NODE_MAX), "STAT_NODE overflow\n");

    return node; 
}

static uint32_t f_idx = 0;
static uint32_t b_idx = STAT_NODE_MAX - 1;

stat_node *find_node_with_path(CPUX86State *env, uint32_t src_addr, 
                        uint32_t path[], uint32_t path_size)
{
    int i;
    bool found;
    stat_node *node, *prev_node;

    found = false;
    /* match src_addr */
    for(i = 0; i < f_idx; i++) {
        node = &cgc->stat_nodes[i];
        if(node->src_addr == src_addr) {
            found = true;
            break;
        }
    }
    if(found == false) {
        /* add new node */
        node = make_stat_node(src_addr, path, f_idx++);
        return node;
    }

    /* match path */
    found = false;
    while(node != NULL) {
        prev_node = node;
        if(memcmp(node->path, path, path_size) == 0) {
            found = true;
            break;
        }
        node = node->next;
    }
    if(found == false) {
        /* add new node */
        node = make_stat_node(src_addr, path, b_idx--);
        prev_node->next = node; 
    }

    return node;
}

void stat_tgt_add_path(CPUX86State *env, uint32_t src_addr, uint32_t tgt_addr)
{
    int i, j;
    uint32_t prev_tb;
    uint32_t path[PATH_DEPTH];
    stat_node *node;

    /* record the last 4 tb */
    //for(i = 0; i < PATH_DEPTH; i++) path[i] = 0;
    memset(path, 0x0, sizeof(path));

    j = env->path_stack_index - 1;
    for(i = 0; i < PATH_DEPTH; i++) {
        j = (j - i);
        if(j < 0) j += PATH_STACK_SIZE;
        prev_tb = *(env->path_stack_base + j);
#ifdef PROF_PATH_WO_IND
	if(prev_tb == PATH_IND_TAG) {
            break;
	}
#endif
	path[i] = prev_tb;
    }

    node = find_node_with_path(env, src_addr, path, sizeof(path));
#if 0
    /* find node */
    for(i = 0; i < cgc->stat_node_count; i++) {
        if(cgc->stat_nodes[i].src_addr == src_addr &&
           !memcmp(cgc->stat_nodes[i].path, path, sizeof(path))) break;
    }

    /* add new node */
    if (i == cgc->stat_node_count) {
        cgc->stat_node_count++;
        cgc->stat_nodes[i].src_addr = src_addr;
        memcpy(cgc->stat_nodes[i].path, path, sizeof(path));
        cgc->stat_nodes[i].tgt_count = 0;
        cgc->stat_nodes[i].tgt_recent_hit = 0;
        ABORT_IF((cgc->stat_node_count == STAT_NODE_MAX), "STAT_NODE overflow\n");
        fprintf(stderr, "%d\n", cgc->stat_node_count);
    }
#endif
    node->tgt_dyn_count++;

    /* find tgt */
    for(i = 0; i < node->tgt_count; i++) {
        if(tgt_addr == node->tgt_addr[i]) {
            node->tgt_addr_hit[i]++;
            break;
        }
    }
    if(i == node->tgt_count) {
        node->tgt_addr[i] = tgt_addr;
        node->tgt_addr_hit[i] = 1;
        node->tgt_count++;
        ABORT_IF((node->tgt_count == STAT_TGT_MAX), "STAT_TGT overflow\n");
    }

    //stat_tgt_recent_once(tgt_addr, node);
    stat_tgt_recent_th(tgt_addr, node, node->tgt_addr_hit[i]);
}
#endif

#define	DPROF_THRESHOLD	100

void stat_tgt_add(TranslationBlock *tb, uint32_t src_addr, uint32_t tgt_addr)
{
    int i;
    stat_node *node;
    TCGContext *cgc = &tcg_ctx;

    /* find node */
    for(i = 0; i < cgc->stat_node_count; i++) {
        if(cgc->stat_nodes[i].src_addr == src_addr) break;
    }
    /* add new node */
    if (i == cgc->stat_node_count) {
        //fprintf(stderr, "new 0x%x\n", tb->pc);
        cgc->stat_node_count++;
        cgc->stat_nodes[i].src_addr = src_addr;
        cgc->stat_nodes[i].tgt_count = 0;
        cgc->stat_nodes[i].tgt_recent_hit = 0;
        ABORT_IF((cgc->stat_node_count == STAT_NODE_MAX), "STAT_NODE overflow\n");
    }

    node = &(cgc->stat_nodes[i]);
    node->tgt_dyn_count++;

    /* find tgt */
    for(i = 0; i < node->tgt_count; i++) {
        if(tgt_addr == node->tgt_addr[i]) {
            node->tgt_addr_hit[i]++;
            break;
        }
    }

    if(i == node->tgt_count) {
        if(i >= STAT_TGT_MAX) {
            fprintf(stderr, "tgt max reached\n");
            i %= STAT_TGT_MAX;
        }
        node->tgt_addr[i] = tgt_addr;
        node->tgt_addr_hit[i] = 1;
        node->tgt_count++;
    }
	/* add by heyu */
#if 0 
	if(node->src_addr == 0x80bd4ea
		#if 1 
		&& (node->tgt_dyn_count % 997) == 0
		#endif
		){
		fprintf(fout, "%x %d\n", node->tgt_addr[i], i); 
		fflush(fout);
	}
#endif
    stat_tgt_recent_th(tgt_addr, node, node->tgt_addr_hit[i]);
#if 0
    stat_tgt_recent_once(tgt_addr, node);
    if(node->tgt_dyn_count == DPROF_THRESHOLD) {
        sort_tgt(node);
    }
#endif
}

static bool path_match(uint32_t path1[], uint32_t path2[])
{
    int i;
    bool is_match;

    is_match = false;

    i = 0;
    while(path1[i] == path2[i]) {
        if(path1[i] == 0 || i == (PATH_DEPTH + 1)) {
            is_match = true;
            break;
        }
        i++;
    }

    return is_match;
}

static int div_64(uint64_t divid, uint64_t divis)
{
    int i;
    
    if (divis == 0) return 0;
    
    i = 0;
    while(divid >= divis) {
        divid -= divis;
        i++;
    }
    
    return i;
}

static char *calc_perc(uint64_t divid, uint64_t divis)
{
    static char result[10];
    int ret;

    ret = div_64(divid * 1000, divis);
    sprintf(result, "%d.%d", ret/10, ret%10);

    return result;
}

/* When the hits of IB reaches DPROF_THRESHOLD, the nodes would be sorted.
   So that the front-n nodes are the prediction targets */
static uint64_t find_prof_tgt_hit(stat_node *node)
{
    uint64_t hits;
    int i;

    hits = 0;
    for(i = 0; i < IND_SLOT_MAX; i++) {
        hits += node->tgt_addr_hit[i];
    }

    return hits;
}

#if 1
static void heapify(uint64_t heap[], int n)
{
    int left, right, swap;
    uint64_t tmp;
    int i;
   
    i = 1;
    while(i <= n/2) {
        left = i * 2;
        right = i * 2 + 1;
        if(right > n) swap = left;
        else if(heap[left] < heap[right]) swap = left;
        else swap = right;

        if(heap[i] < heap[swap]) break;

        //fprintf(stderr, "%lld <-> %lld\n", heap[i], heap[swap]);
        tmp = heap[i];
        heap[i] = heap[swap];
        heap[swap] = tmp;
        i = swap;
        //fprintf(stderr, "*** %lld <-> %lld\n", heap[i], heap[swap]);
    }
}

static uint64_t find_static_max_hit(stat_node *node)
{
    int i;
    uint64_t heap[IND_SLOT_MAX + 1] = {0};
    uint64_t hits, hits_sum;

    for(i = 0; i < node->tgt_count; i++) {
        hits = node->tgt_addr_hit[i];
        if(hits > heap[1]) {
            heap[1] = hits;
            heapify(heap, IND_SLOT_MAX + 1);
        }
    }

    hits_sum = 0;
    for(i = 1; i <= IND_SLOT_MAX; i++) {
        hits_sum += heap[i];
    }

    return hits_sum;
}
#else
static uint64_t find_static_max_hit(stat_node *node)
{
    int i;
    uint64_t max, second_max;

    max = 0;
    second_max = 0;
    for(i = 0; i < node->tgt_count; i++) {
        if(node->tgt_addr_hit[i] > max) {
            second_max = max;
            max = node->tgt_addr_hit[i];
        } else if(node->tgt_addr_hit[i] > second_max) {
            second_max = node->tgt_addr_hit[i];
        }
    }

    return max + second_max;
}
#endif

#ifdef COUNT_PROF
static void calc_ind_hit(void)
{
    uint64_t ind_count, ind_miss;

    ind_count = 0;
    ind_miss = 0;
#ifdef CALL_IND_OPT
    ind_miss += cgc->cind_nothit_count;
    ind_count += cgc->cind_dyn_count;
#endif
#ifdef J_IND_OPT
    ind_miss += cgc->jind_nothit_count;
    ind_count += cgc->jind_dyn_count;
#endif
    fprintf(stderr, "ind_hitrate: %s%%\n",
            calc_perc(ind_count - ind_miss, ind_count));
}
#endif

#if defined(PROF_IND) && defined(COUNT_PROF)
static int ind_prof_stat(void)
{
    int i;
    uint64_t recent_hit_sum, ind_count;
    uint64_t static_max_hit, max_hit_sum;
    uint64_t prof_tgt_hit, prof_hit_sum;
    stat_node *node;
   
    recent_hit_sum = 0;
    max_hit_sum = 0;
    prof_hit_sum = 0;
    ind_count = 0;

#ifdef PROF_JIND
    ind_count += cgc->jind_dyn_count;
#endif
#ifdef PROF_CIND
    ind_count += cgc->cind_dyn_count;
#endif
#ifdef PROF_RET
    ind_count += cgc->rc_miss_count;
#endif
#ifdef PROF_PATH
    memmove(&cgc->stat_nodes[f_idx], &cgc->stat_nodes[b_idx + 1], 
            (STAT_NODE_MAX - b_idx - 1) * sizeof(cgc->stat_nodes[0]));
#endif

    for(i = 0; i < cgc->stat_node_count; i++) {
        node = &(cgc->stat_nodes[i]);
        prof_tgt_hit = find_prof_tgt_hit(node);
        prof_hit_sum += prof_tgt_hit;
        static_max_hit = find_static_max_hit(node);
        max_hit_sum += static_max_hit;
        recent_hit_sum += node->tgt_recent_hit;
#if 1
        int j;
		
        /* print the detail of important IB */
        if(node->tgt_dyn_count > (ind_count >> 7)) {
			fprintf(stderr, "prof_stat: 0x%x\t%u %llu\n", 
                    node->src_addr, node->tgt_count, node->tgt_dyn_count);
            fprintf(stderr, "\trec_hit: %llu %s%%\n", node->tgt_recent_hit,
                    calc_perc(node->tgt_recent_hit,  node->tgt_dyn_count));
            fprintf(stderr, "\tstatic_max_hit: %s%%\n",
                    calc_perc(static_max_hit, node->tgt_dyn_count));
            fprintf(stderr, "\tprof_tgt_hit: %s%%\n",
                    calc_perc(prof_tgt_hit, node->tgt_dyn_count));
            for(j = 0; j < node->tgt_count; j++) {
                fprintf(stderr, "\t\ttarget: 0x%x %llu %s%%\n",
                        node->tgt_addr[j], node->tgt_addr_hit[j],
                        calc_perc(node->tgt_addr_hit[j], 
                                node->tgt_dyn_count));
                       
            }
        }
#endif
    }
#if 0
    fprintf(stderr, "rec_hit_num: %llu\nrec_hitrate: %s%%\n", 
                    recent_hit_sum, calc_perc(recent_hit_sum, ind_count));
    fprintf(stderr, "max_hit_num: %llu\nmax_hitrate: %s%%\n", 
                    max_hit_sum, calc_perc(max_hit_sum, ind_count));
    fprintf(stderr, "prof_hit_num: %llu\nprof_hitrate: %s%%\n", 
                    prof_hit_sum, calc_perc(prof_hit_sum, ind_count));
#endif
    return cgc->stat_node_count;
}
#endif


static uint32_t overlap_stat(void)
{
    int i, j;
    uint32_t overlap_s, overlap_e;
    uint32_t overlap_sum_size;
    SuperTransBlock *stb1, *stb2;
    TCGContext *cgc = &tcg_ctx;

    overlap_sum_size = 0;
    for(i = 0; i < cgc->stb_count; i++) {
        for(j = i + 1; j < cgc->stb_count; j++) {
            if(cgc->stbs[i].pc_start < cgc->stbs[j].pc_start) {
                stb1 = &cgc->stbs[i];
                stb2 = &cgc->stbs[j];
            } else {
                stb1 = &cgc->stbs[j];
                stb2 = &cgc->stbs[i];
            }
            overlap_s = MAX(stb1->pc_start, stb2->pc_start);
            overlap_e = MIN(stb1->pc_end, stb2->pc_end);
         
            if(overlap_s < overlap_e) {
                ///fprintf(stderr, "s:%u e:%u\n", overlap_s, overlap_e);
                overlap_sum_size += (overlap_e - overlap_s);
            }
        }
    }
    return overlap_sum_size;
}

#ifdef RETRANS_IND
static uint64_t jind_hit_stat(uint32_t pc)
{
    int i;
    uint64_t hits;
    stat_node *node;

    hits = 0;
    /* find node */
    for(i = 0; i < cgc->stat_node_count; i++) {
        node = &(cgc->stat_nodes[i]);
        if(node->src_addr == pc) {
            hits += node->tgt_dyn_count;
        }
    }

    return hits;
}

static uint32_t ind_retrans_count = 0;
static uint32_t retrans_tb_count(CPUX86State *env)
{
    int i;
    uint32_t retrans_count_sum;

    retrans_count_sum = 0;
    for(i = 0; i < nb_tbs; i++) {
        if(tbs[i].retransed == true) {
            ind_retrans_count++;
            retrans_count_sum += tbs[i].retrans_count;
        }
    }
    return retrans_count_sum;
}

static void retrans_prof_stat(void)
{
    int i;
    uint32_t ind_miss_count;
    uint64_t total_count;
    uint64_t extra_count;

    total_count = 0;
    extra_count = 0;

    for(i = 0; i < nb_tbs; i++) {
        ind_miss_count = tbs[i].ind_miss_count;
        total_count += ind_miss_count;
        if(ind_miss_count > RETRANS_THRESHOLD) {
            extra_count += (ind_miss_count - RETRANS_THRESHOLD);
        }
    }

    fprintf(stderr, "ind_prof_total_count: %llu\n", total_count);
    fprintf(stderr, "ind_prof_extra_count: %llu\n", extra_count);
}

#endif

void prof_stat(CPUX86State *env, TCGContext *cgc) 
{
    fprintf(stderr, "jmp: \t%d\n", cgc->jmp_count);
    fprintf(stderr, "jcond: \t%d\n", cgc->jcond_count);
    fprintf(stderr, "jothercond: \t%d\n", cgc->jothercond_count);
    fprintf(stderr, "j_ind: \t%d\n", cgc->j_ind_count);
    fprintf(stderr, "call: \t%d\n", cgc->call_count);
    fprintf(stderr, "call_ind: \t%d\n", cgc->call_ind_count);
#ifdef SWITCH_OPT
	fprintf(stderr, "switch-case_num: \t%u\n", sa_num);
	fprintf(stderr, "call-table_num: \t%u\n", call_table);
#endif
    fprintf(stderr, "ret: \t%d\n", cgc->ret_count);
    fprintf(stderr, "retIz: \t%d\n", cgc->retIw_count);
    fprintf(stderr, "direct_trans_count: \t%d\n", 
                     cgc->jmp_count + cgc->jcond_count + cgc->call_count);
    fprintf(stderr, "patch_in_tb_count: \t%d\n", cgc->patch_in_tb_count);
    fprintf(stderr, "find_dest_count: \t%d\n", cgc->find_dest_count);
    fprintf(stderr, "end_by_transnext: \t%d\n", cgc->end_by_transnext);
    fprintf(stderr, "num_tbs: \t%d\n", cgc->tb_ctx.nb_tbs);
    fprintf(stderr, "num_stbs: \t%d\n", cgc->stb_count);
    fprintf(stderr, "prolog_count: \t%d\n", prolog_count);
#ifdef COUNT_PROF
    int tb_not_trans;
    int i;
    tb_not_trans = 0;
    for(i = 0; i < cgc->tb_ctx.nb_tbs; i++) {
        if(cgc->tb_ctx.tbs[i].tc_ptr == (uint8_t *)NOT_TRANS_YET) tb_not_trans++;
    }
    fprintf(stderr, "tb_not_trans: \t%d\n", tb_not_trans);

#ifdef COUNT_INSN
    fprintf(stderr, "insn_dyn: \t%llu\n", cgc->insn_dyn_count);
    fprintf(stderr, "IB_dyn_rate:\t%s\n", calc_perc(cgc->jind_dyn_count + cgc->cind_dyn_count, cgc->insn_dyn_count));
#endif
    fprintf(stderr, "ret_dyn: \t%llu\n", cgc->ret_dyn_count);
    fprintf(stderr, "rc_miss_dyn: \t%llu\n", cgc->rc_miss_count);
#ifdef RC_IND_OPT
    fprintf(stderr, "rc_ind_dyn: \t%llu\n", cgc->rc_ind_dyn_count);
    fprintf(stderr, "rc_ind_nothit: \t%llu\n", cgc->rc_ind_nothit_count);
#endif
#ifdef RAS_OPT
    fprintf(stderr, "ras_dyn: \t%llu\n", cgc->ras_dyn_count);
    fprintf(stderr, "ras_miss_dyn: \t%llu\n", cgc->ras_miss_count);
    fprintf(stderr, "callstack_size: \t\t%d\n",
                     env->call_stack_ptr - env->call_stack_base);
#endif
    fprintf(stderr, "sv_miss_dyn: \t%u\n", cgc->sv_miss_count);
    fprintf(stderr, "sv_travel_dyn: \t%llu\n", cgc->sv_travel_count);
    fprintf(stderr, "jind_dyn: \t%llu\n", cgc->jind_dyn_count);
    fprintf(stderr, "cind_dyn: \t%llu\n", cgc->cind_dyn_count);


#ifdef J_IND_OPT
    fprintf(stderr, "jind_nothit: \t%llu\n", cgc->jind_nothit_count);
#endif
#ifdef CALL_IND_OPT
    fprintf(stderr, "cind_nothit: \t%llu\n", cgc->cind_nothit_count);
#endif
#ifdef RETRANS_IND
    fprintf(stderr, "retrans_tb_count: \t%u\n", retrans_tb_count(env));
    fprintf(stderr, "retrans_tb_rate: \t%s%%\n", 
                     calc_perc(retrans_tb_count(env), nb_tbs));
    fprintf(stderr, "retrans_ind_count: \t%u\n", ind_retrans_count);
    fprintf(stderr, "retrans_ind_rate: \t%s%%\n", 
                     calc_perc(ind_retrans_count, 
                               cgc->call_ind_count + cgc->j_ind_count));
    //retrans_prof_stat();
    //retrans_count_stat(env);
#endif
#ifdef IND_OPT
    calc_ind_hit();
#endif
#endif

#ifdef COUNT_PROF
    int sieve_sum;
    sieve_sum = 0;
    for(i = 0; i < SIEVE_SIZE; i++) {
        sieve_sum += cgc->sieve_stat[i]; 
    }
    fprintf(stderr, "sieve_sum: \t%d\n", sieve_sum);
#endif

    fprintf(stderr, "s_code_size: \t\t%u\n", cgc->s_code_size);
#ifdef COUNT_PROF
    fprintf(stderr, "overlap_size: \t\t%u\n", overlap_stat());
#endif
    uint32_t code_ptr_size, sieve_ptr_size;
    code_ptr_size = cgc->code_gen_ptr - cgc->code_gen_buffer;
    sieve_ptr_size = cgc->sieve_code_ptr - cgc->sieve_buffer;
    fprintf(stderr, "codecache_size: \t%u\n", code_ptr_size);
    fprintf(stderr, "sieve_size: \t\t%d\n", sieve_ptr_size);
    fprintf(stderr, "totalcode_size: \t%d\n", sieve_ptr_size + code_ptr_size);
#if defined(PROF_IND) && defined(COUNT_PROF)
    fprintf(stderr, "ind2: \t%d\n", ind_prof_stat());
#endif
}

