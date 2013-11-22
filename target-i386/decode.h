#ifndef DECODE_H
#define DECODE_H
/*
 * Copyright (c) 2005, Johns Hopkins University and The EROS Group, LLC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 *  * Neither the name of the Johns Hopkins University, nor the name
 *    of The EROS Group, LLC, nor the names of their contributors may
 *    be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Attribute values indicating a need for further processing based on
   last byte fetched */

#include <stdio.h>
#include "cpu.h"

#ifndef CONST_TABLE
#define CONST_TABLE const
#endif

#define DF_NONE                   0x0u
#define DF_MODRM                  0x1u	/* Has mod/rm field */
#define DF_Ib                     0x2u	/* Has immediate operand byte */
#define DF_Jb                     0x2u	/* Has byte branch offset */
#define DF_Iv                     0x8u     /* Has mode-dependent operand immediate */
#define DF_Jv                    0x10u  /* Has mode-dependent address immediate */
#define DF_rel                   0x10u 	/* Has mode-dependent address immediate */
#define DF_Ob                    0x40u	/* Has byte offset */
#define DF_Ov                    0x80u 	/* Has mode-dependent address immediate */
#define DF_PREFIX               0x100u	/* opcode prefix byte */
#define DF_UNDEFINED            0x200u	/* undefined opcode */
#define DF_TABLE                0x400u
#define DF_GROUP                0x800u
#define DF_r8	               0x1000u	/* reg8 has unusual modrm decoding */
#define DF_rm8	               0x2000u	/* rm8 has unusual modrm decoding */
#define DF_Iw                  0x4000u	/* mode-independent imm16 */
#define DF_Ap                  0x8000u	/* 4 byte or 6 byte direct address operand */
/* Following flags are for the use of floating-point operations only */
#define DF_FLOAT      	      0x10000u	/* floating point opcode */
#define DF_ONE_MORE_LEVEL     0x20000u    /* Needs an additional level of indexing */
#define DF_BINARY	      0x40000u	/* Is it a binary floating-point operation? */
#define DF_DIRECTION          0x80000u    /* ST(0), ST(i) --> 0; ST(i), ST(0) --> 1 */
/* Is the Address-Size Override Prefix Legal for this instruction */
#define DF_ADDRSZ_PREFIX     0x100000u	
/* Is the Operand-Size Override Prefix Legal for this instruction */
#define DF_OPSZ_PREFIX       0x200000u   
/* MMX / SSE instructions have special meaning for some prefixes */
#define DF_MMX_SSE           0x400000u
#define DF_BRANCH            0x800000u
/* Following type ensures that opcode structure is 32 bytes long */
#define MODETYPE unsigned char

typedef struct {
  MODETYPE amode;		/* addressing mode */
  MODETYPE ainfo;		/* mode-specific info */
} OpArgument;

#define OP_MAXARG 3
typedef struct { 
  unsigned long index;		/* sanity check */

  const char *disasm;			/* dissassembly string */

  OpArgument args[OP_MAXARG];

  CONST_TABLE void *ptr;

  int inst_type;

  unsigned long attr;

  unsigned long flag_effect;	/* Whether the instruction sources/sinks/both the flags */
} OpCode __attribute__ ((aligned (32)));

typedef enum {
    INST_NORMAL = 0,
    INST_CALL,
    INST_CALL_IND,
    INST_JMP,
    INST_JMP_IND,
    INST_JCOND,
    INST_OTHER_JCOND,
    INST_RET,
    INST_RET_IW,
    INST_INT,
    INST_RESERVED,

    INST_GROUP1_EB_IB,
    INST_GROUP1_EV_IV,
    INST_GROUP1_EV_IB,
    INST_GROUP2_EB_1,
    INST_GROUP2_EV_1,
    INST_GROUP2_EB_CL,
    INST_GROUP2_EV_CL,
    INST_GROUP2A_EB_IB,
    INST_GROUP2A_EV_IB,
    INST_GROUP3B,
    INST_GROUP3V,
    INST_NGROUP4,
    INST_NGROUP5,
    INST_NGROUP6,
    INST_NGROUP7,
    INST_NGROUP9,
    INST_GROUP8_EV_IB,
    INST_2BYTES_OPC,
    INST_PREFIX,
    INST_SYSENTER,
} enum_inst_type;

typedef enum {
    INST_FLOAT_D8 = 50,
    INST_FLOAT_D9,
    INST_FLOAT_DA,
    INST_FLOAT_DB,
    INST_FLOAT_DC,
    INST_FLOAT_DD,
    INST_FLOAT_DE,
    INST_FLOAT_DF,
    INST_FLOAT_D9_2,
    INST_FLOAT_D9_4,
    INST_FLOAT_D9_5,
    INST_FLOAT_D9_6,
    INST_FLOAT_D9_7,
    INST_FLOAT_DA_5,
    INST_FLOAT_DB_4,
    INST_FLOAT_DE_3,
    INST_FLOAT_DF_4,
} enum_float_inst_type;

#define DSFL_GROUP1_PREFIX    0x1u
#define DSFL_GROUP2_PREFIX    0x2u
#define DSFL_GROUP3_PREFIX    0x4u
#define DSFL_GROUP4_PREFIX    0x8u

#define OPSTATE_ADDR32 0x1u
#define OPSTATE_DATA32 0x2u

#define OPSTATE_ADDR16 0x0u
#define OPSTATE_DATA16 0x0u

/* modrm byte */
typedef union modrm_union modrm_union;
union modrm_union {
  struct {
    unsigned char rm : 3;
    unsigned char reg : 3;
    unsigned char mod : 2;
  } parts; 
  unsigned char byte;
};

/* sib byte */
typedef union sib_union sib_union;
union sib_union {
  struct {
    unsigned char base : 3;
    unsigned char index : 3;
    unsigned char ss : 2;
  } parts;
  unsigned char byte;
};

#define GP_REG_EAX      0x0u
#define GP_REG_ECX      0x1u
#define GP_REG_EDX      0x2u
#define GP_REG_EBX      0x3u
#define GP_REG_ESP      0x4u
#define GP_REG_EBP      0x5u
#define GP_REG_ESI      0x6u
#define GP_REG_EDI      0x7u

#define HD_PREFIX_REPZ	0xf3u
#define HD_PREFIX_REPNZ	0xf2u
#define HD_PREFIX_LOCK	0xf0u

#define HD_PREFIX_CS	0x2eu
#define HD_PREFIX_DS	0x3eu
#define HD_PREFIX_ES	0x26u
#define HD_PREFIX_FS	0x64u
#define HD_PREFIX_GS	0x65u
#define HD_PREFIX_SS	0x36u

#define HD_PREFIX_OPSZ	0x66u
#define HD_PREFIX_ADDRSZ	0x67u

#ifdef SUPERVISOR_MODE
#define IS_IFAULT(b) ((b) > 255u)
#else
#define IS_IFAULT(b) (0)
#endif

typedef struct decode_s decode_t;
struct decode_s {
  unsigned long decode_eip; /* Start of the Guest Instruction */

  unsigned char *instr;	 /* Pointer to the instruction AFTER ALL the 
			    Prefix Bytes */
  unsigned char *pInstr; /* End of Instruction pointer. 
			    Actually holds the start of next Instruction */			    
  unsigned attr;

  unsigned char Group1_Prefix;
  unsigned char Group2_Prefix;
  unsigned char Group3_Prefix;
  unsigned char Group4_Prefix;
  unsigned char no_of_prefixes;
  unsigned flags;

  bool (*emitfn)(CPUX86State *loc_env, TCGContext *cgc, decode_t *ds);
  const void *pEntry;		/* for disassembly */

  unsigned long b;
  unsigned opstate;

  /* Saved pieces of the opcode, where applicable: */
  /* The modrm byte: */
  modrm_union modrm;

  /* Decode of the SIB byte: */
  unsigned char need_sib;
  sib_union sib;

  unsigned dispBytes;		/* displacement length */
  long displacement;		/* SIGNED displacement */

  /* Registers implicated by the modrm and sib bytes */
  unsigned long modrm_regs;

  long immediate;		/* SIGNED immediate */
  long imm16;			/* used in ENTER, RET */

  int inst_type;

};

uint32_t simple_disas_insn(decode_t *ds, target_ulong pc);

#ifdef MODETYPE
#define MODE(x) ((MODETYPE) (x))
#else
#define MODE(x) (x)
#endif

/* decoding modes: */
#define b_mode MODE(0x1u)
#define v_mode MODE(0x2u)
#define w_mode MODE(0x3u)
#define d_mode MODE(0x4u)
#define p_mode MODE(0x5u)
#define s_mode MODE(0x6u)
#define q_mode MODE(0x7u) /* Quadword (64-bit) or Double Real */
#define x_mode MODE(0x7u) /* 98 / 108 bytes */
#define y_mode MODE(0x8u) /* extended real or BCD decimal (80-bit) */
#define z_mode MODE(0x9u) /* m14/28 bytes */

#define reg_AH  MODE(0x80u)
#define reg_AL  MODE(0x81u)
#define reg_BH  MODE(0x82u)
#define reg_BL  MODE(0x83u)
#define reg_CH  MODE(0x84u)
#define reg_CL  MODE(0x85u)
#define reg_DH  MODE(0x86u)
#define reg_DL  MODE(0x87u)
#define reg_DX  MODE(0x88u)
#define reg_indirDX  MODE(0x89u)	/* decoding hack */

#define reg_EAX MODE(0x90u)
#define reg_EBX MODE(0x91u)
#define reg_ECX MODE(0x92u)
#define reg_EDX MODE(0x93u)
#define reg_ESP MODE(0x94u)
#define reg_EBP MODE(0x95u)
#define reg_EDI MODE(0x96u)
#define reg_ESI MODE(0x97u)

#define reg_ES  MODE(0x0u)
#define reg_CS  MODE(0x1u)
#define reg_SS  MODE(0x2u)
#define reg_DS  MODE(0x3u)
#define reg_FS  MODE(0x4u)
#define reg_GS  MODE(0x5u)

#define ADDR_none    MODE(0u)
#define ADDR_implied_reg MODE(0x1u)
#define ADDR_E       MODE(0x2u)
#define ADDR_G       MODE(0x3u)
#define ADDR_imm     MODE(0x4u)
#define ADDR_es      MODE(0x5u)
#define ADDR_ds      MODE(0x6u)
#define ADDR_jmp     MODE(0x7u)
#define ADDR_seg     MODE(0x8u)
#define ADDR_seg_reg MODE(0x9u)
#define ADDR_direct  MODE(0xau)
#define ADDR_offset  MODE(0xbu)
#define ADDR_FREG    MODE(0xcu)

#define ADDR_R MODE(0xeu) /* mod field of modR/M must name a register */
#define ADDR_C MODE(0xfu) /* reg field of modR/M names a control register*/
#define ADDR_D MODE(0x10u) /* reg field of modR/M names a debug register*/
#define ADDR_T MODE(0x11u) /* reg field of modR/M names a test register*/


/* Flag effect declaration */
#define NF      0x00u	        // No effect
#define RCF     0x01u    	// Reads CF
#define WCF     0x02u	        // Modifies CF
#define RAOF    0x04u	        // Reads any other flag
#define WAOF    0x08u	        // Modifies any other flag
#define RF      (RCF | RAOF)	// Reads at least one flag
#define WF      (WCF | WAOF)    // Modifies at least one flag
#define RWCF    (RCF | WCF)     // Reads and Modifies the Carry Flag
#define RWF     (RF | WF)	// Reads at least one flag and writes at least one flag
#define NDF     WF	        // Non-Deterministic, as per manual
#define UF      RWF	        // Unsure
#define WPF     RWF             // Modifies a part of the flags that
                                // are not tracked   

#define SOURCES_FLAGS(p)   (p->flag_effect & RF)
#define MODIFIES_FLAGS(p)  (p->flag_effect & WF)
#define SOURCES_OSZAPF(p)  (p->flag_effect & RAOF)
#define MODIFIES_OSZAPF(p) (p->flag_effect & WAOF)
#define SOURCES_CF(p)      (p->flag_effect & RCF)
#define MODIFIES_CF(p)     (p->flag_effect & WCF)

extern CONST_TABLE OpCode nopbyte0[256];
extern CONST_TABLE OpCode twoByteOpcodes[256];

extern CONST_TABLE OpCode group1_Eb_Ib[8];
extern CONST_TABLE OpCode group1_Ev_Iv[8];
extern CONST_TABLE OpCode group1_Ev_Ib[8];
extern CONST_TABLE OpCode group2a_Eb_Ib[8];
extern CONST_TABLE OpCode group2a_Ev_Ib[8];
extern CONST_TABLE OpCode group2_Eb_1[8];
extern CONST_TABLE OpCode group2_Ev_1[8];
extern CONST_TABLE OpCode group2_Eb_CL[8];
extern CONST_TABLE OpCode group2_Ev_CL[8];
extern CONST_TABLE OpCode group3b[8];
extern CONST_TABLE OpCode group3v[8];
extern CONST_TABLE OpCode ngroup4[8];
extern CONST_TABLE OpCode ngroup5[8];
extern CONST_TABLE OpCode ngroup6[8];
extern CONST_TABLE OpCode ngroup7[8];
extern CONST_TABLE OpCode group8_Ev_Ib[8];
extern CONST_TABLE OpCode ngroup9[8];

extern CONST_TABLE OpCode float_d8[16];

extern CONST_TABLE OpCode float_d9[16];
extern CONST_TABLE OpCode float_d9_2[8];
extern CONST_TABLE OpCode float_d9_4[8];
extern CONST_TABLE OpCode float_d9_5[8];
extern CONST_TABLE OpCode float_d9_6[8];
extern CONST_TABLE OpCode float_d9_7[8];

extern CONST_TABLE OpCode float_da[16];
extern CONST_TABLE OpCode float_da_5[8];

extern CONST_TABLE OpCode float_db[16];
extern CONST_TABLE OpCode float_db_4[8];

extern CONST_TABLE OpCode float_dc[16];

extern CONST_TABLE OpCode float_dd[16];

extern CONST_TABLE OpCode float_de[16];
extern CONST_TABLE OpCode float_de_3[8];

extern CONST_TABLE OpCode float_df[16];
extern CONST_TABLE OpCode float_df_4[8];

#endif /* DECODE_H */
