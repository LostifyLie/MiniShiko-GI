#pragma once
#include <cstdint>

#define F_MODRM    0x00000001
#define F_SIB      0x00000002
#define F_IMM8     0x00000004
#define F_IMM16    0x00000008
#define F_IMM32    0x00000010
#define F_IMM64    0x00000020
#define F_DISP8    0x00000040
#define F_DISP16   0x00000080
#define F_DISP32   0x00000100
#define F_RELATIVE 0x00000200
#define F_ERROR    0x00001000

#pragma pack(push, 1)
struct hde64s
{
    uint8_t  len;
    uint8_t  p_rep;
    uint8_t  p_lock;
    uint8_t  p_seg;
    uint8_t  p_66;
    uint8_t  p_67;
    uint8_t  rex;
    uint8_t  rex_w;
    uint8_t  rex_r;
    uint8_t  rex_x;
    uint8_t  rex_b;
    uint8_t  opcode;
    uint8_t  opcode2;
    uint8_t  modrm;
    uint8_t  modrm_mod;
    uint8_t  modrm_reg;
    uint8_t  modrm_rm;
    uint8_t  sib;
    uint8_t  sib_scale;
    uint8_t  sib_index;
    uint8_t  sib_base;
    union { uint8_t imm8; uint16_t imm16; uint32_t imm32; uint64_t imm64; } imm;
    union { uint8_t disp8; uint16_t disp16; uint32_t disp32; } disp;
    uint32_t flags;
};
#pragma pack(pop)

unsigned int hde64_disasm(const void* code, hde64s* hs);
