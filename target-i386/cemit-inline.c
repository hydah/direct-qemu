#include "emit.h"


#define MODRM(mod, reg, rm)    ((mod<<6) | (reg<<3) | rm)

#define OP_PUSH_Iz    0x68
#define OP_MOV_G_E    0x89
#define OP_MOV_E_G    0x8b
#define OP_LEA_M_G    0x8d
#define OP_GROUP11    0xc7

static inline void cemit_mov_IM_G(TCGContext *cgc, uint32_t addr, int reg)
{
    code_emit8(cgc->code_ptr, OP_MOV_E_G);
    code_emit8(cgc->code_ptr, MODRM(0x0, reg, 0x5));
    code_emit32(cgc->code_ptr, addr);
}

static inline void cemit_mov_G_IM(TCGContext *cgc, int reg, uint32_t addr)
{
    code_emit8(cgc->code_ptr, OP_MOV_G_E);
    code_emit8(cgc->code_ptr, MODRM(0x0, reg, 0x5));
    code_emit32(cgc->code_ptr, addr);
}

static inline void cemit_mov_I_IM(TCGContext *cgc, uint32_t imm32, int mem)
{

}

static inline void cemit_mov_I_GM(TCGContext *cgc, uint32_t imm32, int reg)
{
    code_emit8(cgc->code_ptr, OP_GROUP11);
    code_emit8(cgc->code_ptr, MODRM(0, 0, reg));
    code_emit32(cgc->code_ptr, imm32);
}

static inline void cemit_push_I(TCGContext *cgc, uint32_t imm32)
{
    code_emit8(cgc->code_ptr, OP_PUSH_Iz); /* PUSH */
    code_emit32(cgc->code_ptr, imm32);
}

static inline void cemit_lea_reg(TCGContext *cgc, int reg, int offset)
{
    uint8_t modrm;

    if(offset < 0)
        modrm = MODRM(0x1, reg, reg);
    else
        modrm = MODRM(0x2, reg, reg);

    if(reg == R_ESP) {
        code_emit8(cgc->code_ptr, OP_LEA_M_G); 
        code_emit8(cgc->code_ptr, modrm);
        code_emit8(cgc->code_ptr, 0x24); /* 00 100 100 */
    } else {
        code_emit8(cgc->code_ptr, OP_LEA_M_G); 
        code_emit8(cgc->code_ptr, modrm);
    }

    if(offset < 0)
        code_emit8(cgc->code_ptr, offset);
    else
        code_emit32(cgc->code_ptr, (uint32_t)offset);
}

static inline void cemit_incl_mem(TCGContext *cgc, uint32_t addr) 
{
    /* pushf */
    code_emit8(cgc->code_ptr, 0x9c);
    /* incl (addr) */
    code_emit8(cgc->code_ptr, 0xff);
    code_emit8(cgc->code_ptr, 0x05); /* ModRM = 00 000 101b */
    code_emit32(cgc->code_ptr, addr);
    /* popf */
    code_emit8(cgc->code_ptr, 0x9d);
}

static inline void cemit_incl_mem64(TCGContext *cgc, uint32_t addr) 
{
    /* pushf */
    code_emit8(cgc->code_ptr, 0x9c);

    /* add $1, (addr) */
    code_emit8(cgc->code_ptr, 0x83);
    code_emit8(cgc->code_ptr, 0x05); /* ModRM = 00 000 101b */
    code_emit32(cgc->code_ptr, addr);
    code_emit8(cgc->code_ptr, 1);
    /* adc $0, (addr + 4) */
    code_emit8(cgc->code_ptr, 0x83);
    code_emit8(cgc->code_ptr, 0x15); /* ModRM = 00 010 101b */
    code_emit32(cgc->code_ptr, addr + 4);
    code_emit8(cgc->code_ptr, 0);
    /* popf */
    code_emit8(cgc->code_ptr, 0x9d);
}

static inline void cemit_add_mem64(TCGContext *cgc, uint32_t addr, uint32_t val)
{
    /* pushf */
    code_emit8(cgc->code_ptr, 0x9c);

    /* addl $val, (addr) */
    code_emit8(cgc->code_ptr, 0x81);
    code_emit8(cgc->code_ptr, 0x05); /* ModRM = 00 000 101b */
    code_emit32(cgc->code_ptr, addr);
    code_emit32(cgc->code_ptr, val);
    /* adcl $0, (addr + 4) */
    code_emit8(cgc->code_ptr, 0x83);
    code_emit8(cgc->code_ptr, 0x15); /* ModRM = 00 010 101b */
    code_emit32(cgc->code_ptr, addr + 4);
    code_emit8(cgc->code_ptr, 0);
    /* popf */
    code_emit8(cgc->code_ptr, 0x9d);
}

