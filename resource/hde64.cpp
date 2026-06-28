#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <cstdint>
#include <cstring>
#include "hde64.h"

#define C_NONE    0x00
#define C_MODRM   0x01
#define C_IMM8    0x02
#define C_IMM16   0x04
#define C_IMM64   0x08
#define C_IMM_P66 0x10
#define C_REL8    0x20
#define C_REL32   0x40
#define C_GROUP   0x80
#define C_ERROR   0xFF

static const uint8_t hde64_table_1byte[256] = {
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM_P66, C_NONE, C_NONE,
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    C_NONE, C_NONE, C_MODRM, C_MODRM, C_NONE, C_NONE, C_NONE, C_NONE,
    C_IMM_P66, C_MODRM|C_IMM_P66, C_IMM8, C_MODRM|C_IMM8, C_NONE, C_NONE, C_NONE, C_NONE,
    C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8,
    C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8,
    C_MODRM|C_IMM8, C_MODRM|C_IMM_P66, C_MODRM|C_IMM8, C_MODRM|C_IMM8,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    C_IMM64, C_IMM64, C_IMM64, C_IMM64, C_NONE, C_NONE, C_NONE, C_NONE,
    C_IMM8, C_IMM_P66, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    C_IMM8, C_IMM8, C_IMM8, C_IMM8, C_IMM8, C_IMM8, C_IMM8, C_IMM8,
    C_IMM64, C_IMM64, C_IMM64, C_IMM64, C_IMM64, C_IMM64, C_IMM64, C_IMM64,
    C_MODRM|C_IMM8, C_MODRM|C_IMM8, C_IMM16, C_NONE, C_MODRM, C_MODRM,
    C_MODRM|C_IMM8, C_MODRM|C_IMM_P66, C_IMM16|C_IMM8, C_NONE, C_IMM16, C_NONE,
    C_NONE, C_IMM8, C_NONE, C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8, C_IMM8, C_NONE, C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_REL8, C_REL8, C_REL8, C_REL8, C_IMM8, C_IMM8, C_IMM8, C_IMM8,
    C_REL32, C_REL32, C_NONE, C_REL8, C_NONE, C_NONE, C_NONE, C_NONE,
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_MODRM|C_GROUP, C_MODRM|C_GROUP,
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_MODRM, C_MODRM,
};

static const uint8_t hde64_table_2byte[256] = {
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_ERROR, C_NONE, C_NONE, C_NONE,
    C_NONE, C_NONE, C_ERROR, C_NONE, C_ERROR, C_MODRM, C_NONE, C_MODRM|C_IMM8,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_ERROR, C_ERROR, C_ERROR, C_ERROR,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_ERROR, C_NONE,
    C_MODRM, C_ERROR, C_MODRM, C_ERROR, C_ERROR, C_ERROR, C_ERROR, C_ERROR,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM|C_IMM8, C_MODRM|C_IMM8, C_MODRM|C_IMM8, C_MODRM|C_IMM8,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32,
    C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_NONE, C_NONE, C_NONE, C_MODRM, C_MODRM|C_IMM8, C_MODRM, C_ERROR, C_ERROR,
    C_NONE, C_NONE, C_NONE, C_MODRM, C_MODRM|C_IMM8, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM|C_IMM8, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM|C_IMM8, C_MODRM, C_MODRM|C_IMM8, C_MODRM|C_IMM8,
    C_MODRM|C_IMM8, C_MODRM,
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_ERROR,
};

unsigned int hde64_disasm(const void* code, hde64s* hs)
{
    const uint8_t* p = (const uint8_t*)code;
    memset(hs, 0, sizeof(hde64s));

    uint8_t rexW = 0;
    int operandSize = 4;

    for (;;) {
        uint8_t c = *p;
        switch (c) {
        case 0xF3: hs->p_rep = c; p++; continue;
        case 0xF2: hs->p_rep = c; p++; continue;
        case 0xF0: hs->p_lock = c; p++; continue;
        case 0x26: case 0x2E: case 0x36: case 0x3E: case 0x64: case 0x65:
            hs->p_seg = c; p++; continue;
        case 0x66: hs->p_66 = c; operandSize = 2; p++; continue;
        case 0x67: hs->p_67 = c; p++; continue;
        }
        if ((c & 0xF0) == 0x40) {
            hs->rex = c;
            hs->rex_w = (c >> 3) & 1;
            hs->rex_r = (c >> 2) & 1;
            hs->rex_x = (c >> 1) & 1;
            hs->rex_b = c & 1;
            rexW = hs->rex_w;
            if (rexW) operandSize = 8;
            p++;
            continue;
        }
        break;
    }

    uint8_t op = *p++;
    hs->opcode = op;

    bool twoByteOp = false;
    uint8_t tblFlags;

    if (op == 0x0F) {
        twoByteOp = true;
        uint8_t op2 = *p++;
        hs->opcode2 = op2;
        tblFlags = hde64_table_2byte[op2];
    } else {
        tblFlags = hde64_table_1byte[op];
    }

    if (tblFlags == C_ERROR) {
        hs->flags |= F_ERROR;
        hs->len = (uint8_t)(p - (const uint8_t*)code);
        return hs->len;
    }

    if (tblFlags & C_REL8) {
        hs->flags |= F_IMM8 | F_RELATIVE;
        hs->imm.imm8 = *p++;
        hs->len = (uint8_t)(p - (const uint8_t*)code);
        return hs->len;
    }
    if (tblFlags & C_REL32) {
        hs->flags |= F_IMM32 | F_RELATIVE;
        hs->imm.imm32 = *(uint32_t*)p; p += 4;
        hs->len = (uint8_t)(p - (const uint8_t*)code);
        return hs->len;
    }

    if (tblFlags & C_MODRM) {
        uint8_t modrm = *p++;
        hs->modrm = modrm;
        hs->flags |= F_MODRM;
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t reg = (modrm >> 3) & 7;
        uint8_t rm  = modrm & 7;
        hs->modrm_mod = mod;
        hs->modrm_reg = reg;
        hs->modrm_rm  = rm;

        if (mod != 3 && rm == 4) {
            hs->sib = *p++;
            hs->flags |= F_SIB;
            hs->sib_scale = (hs->sib >> 6) & 3;
            hs->sib_index = (hs->sib >> 3) & 7;
            hs->sib_base  = hs->sib & 7;
            if (mod == 0 && hs->sib_base == 5) {
                hs->disp.disp32 = *(uint32_t*)p; p += 4;
                hs->flags |= F_DISP32;
            }
        }

        if (mod == 0 && rm == 5) {
            hs->disp.disp32 = *(uint32_t*)p; p += 4;
            hs->flags |= F_DISP32;
        } else if (mod == 1) {
            hs->disp.disp8 = *p++;
            hs->flags |= F_DISP8;
        } else if (mod == 2) {
            hs->disp.disp32 = *(uint32_t*)p; p += 4;
            hs->flags |= F_DISP32;
        }

        if (!twoByteOp && (op == 0xF6 || op == 0xF7) && reg <= 1) {
            if (op == 0xF6) tblFlags |= C_IMM8;
            else            tblFlags |= C_IMM_P66;
        }
    }

    if (tblFlags & C_IMM8) {
        hs->imm.imm8 = *p++;
        hs->flags |= F_IMM8;
    }
    if (tblFlags & C_IMM16) {
        hs->imm.imm16 = *(uint16_t*)p; p += 2;
        hs->flags |= F_IMM16;
    }
    if (tblFlags & C_IMM_P66) {
        if (operandSize == 2) {
            hs->imm.imm16 = *(uint16_t*)p; p += 2;
            hs->flags |= F_IMM16;
        } else {
            hs->imm.imm32 = *(uint32_t*)p; p += 4;
            hs->flags |= F_IMM32;
        }
    }
    if (tblFlags & C_IMM64) {
        if (rexW) {
            hs->imm.imm64 = *(uint64_t*)p; p += 8;
            hs->flags |= F_IMM64;
        } else if (operandSize == 2) {
            hs->imm.imm16 = *(uint16_t*)p; p += 2;
            hs->flags |= F_IMM16;
        } else {
            hs->imm.imm32 = *(uint32_t*)p; p += 4;
            hs->flags |= F_IMM32;
        }
    }

    hs->len = (uint8_t)(p - (const uint8_t*)code);
    return hs->len;
}
