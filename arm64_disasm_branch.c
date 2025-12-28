/**
 * ARM64反汇编器 - 分支指令解析（表驱动版本）
 * 包括B、BL、BR、BLR、RET、CBZ、CBNZ等
 */

#include "arm64_disasm.h"
#include "arm64_decode_table.h"
#include <stdio.h>
#include <string.h>

/* ========== 分支指令解码函数 ========== */

/**
 * 解析无条件分支（立即数）- B/BL
 * 编码：op|00101|imm26
 * mask: 0x7C000000, value: 0x14000000 (B) / 0x94000000 (BL)
 */
static bool decode_uncond_branch_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t op = BIT(inst, 31);
    int32_t imm26 = BITS(inst, 0, 25);
    
    result->imm = SIGN_EXTEND(imm26, 26) << 2;
    result->has_imm = true;
    
    if (op == 0) {
        SAFE_STRCPY(result->mnemonic, "b");
        result->type = INST_TYPE_B;
    } else {
        SAFE_STRCPY(result->mnemonic, "bl");
        result->type = INST_TYPE_BL;
    }
    
    return true;
}

/**
 * 解析条件分支（立即数）- B.cond
 * 编码：0101010|0|imm19|0|cond
 * mask: 0xFF000010, value: 0x54000000
 */
static bool decode_cond_branch_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    int32_t imm19 = BITS(inst, 5, 23);
    uint8_t cond = BITS(inst, 0, 3);
    
    result->imm = SIGN_EXTEND(imm19, 19) << 2;
    result->has_imm = true;
    result->type = INST_TYPE_B;
    
    static const char *cond_names[] = {
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
        "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
    };
    
    if (cond < 16) {
        snprintf(result->mnemonic, sizeof(result->mnemonic), "b.%s", cond_names[cond]);
    } else {
        return false;
    }
    
    return true;
}

/**
 * 解析比较并分支 - CBZ/CBNZ
 * 编码：sf|011010|op|imm19|Rt
 * mask: 0x7E000000, value: 0x34000000
 */
static bool decode_compare_branch(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t op = BIT(inst, 24);
    int32_t imm19 = BITS(inst, 5, 23);
    uint8_t rt = BITS(inst, 0, 4);
    
    result->rd = rt;
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->imm = SIGN_EXTEND(imm19, 19) << 2;
    result->has_imm = true;
    result->is_64bit = sf;
    
    if (op == 0) {
        SAFE_STRCPY(result->mnemonic, "cbz");
        result->type = INST_TYPE_CBZ;
    } else {
        SAFE_STRCPY(result->mnemonic, "cbnz");
        result->type = INST_TYPE_CBNZ;
    }
    
    return true;
}

/**
 * 解析测试位并分支 - TBZ/TBNZ
 * 编码：b5|011011|op|b40|imm14|Rt
 * mask: 0x7E000000, value: 0x36000000
 */
static bool decode_test_branch(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t b5 = BIT(inst, 31);
    uint8_t op = BIT(inst, 24);
    uint8_t b40 = BITS(inst, 19, 23);
    int16_t imm14 = BITS(inst, 5, 18);
    uint8_t rt = BITS(inst, 0, 4);
    
    uint8_t bit_pos = (b5 << 5) | b40;
    
    result->rd = rt;
    result->rd_type = (bit_pos < 32) ? REG_TYPE_W : REG_TYPE_X;
    result->imm = SIGN_EXTEND(imm14, 14) << 2;
    result->shift_amount = bit_pos;
    result->has_imm = true;
    result->is_64bit = (bit_pos >= 32);
    
    if (op == 0) {
        SAFE_STRCPY(result->mnemonic, "tbz");
        result->type = INST_TYPE_TBZ;
    } else {
        SAFE_STRCPY(result->mnemonic, "tbnz");
        result->type = INST_TYPE_TBNZ;
    }
    
    return true;
}

/**
 * 解析无条件分支（寄存器）- BR/BLR/RET
 * 编码：1101011|opc|op2|op3|Rn|op4
 * mask: 0xFE000000, value: 0xD6000000
 */
static bool decode_uncond_branch_reg(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t opc = BITS(inst, 21, 24);
    uint8_t op2 = BITS(inst, 16, 20);
    uint8_t op3 = BITS(inst, 10, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t op4 = BITS(inst, 0, 4);
    
    result->rn = rn;
    result->rn_type = REG_TYPE_X;
    result->has_imm = false;
    result->is_64bit = true;
    
    if (op2 != 31 || op4 != 0) {
        return false;
    }
    
    switch (opc) {
        case 0x00:  /* BR */
            if (op3 == 0) {
                SAFE_STRCPY(result->mnemonic, "br");
                result->type = INST_TYPE_BR;
                return true;
            }
            break;
        case 0x01:  /* BLR */
            if (op3 == 0) {
                SAFE_STRCPY(result->mnemonic, "blr");
                result->type = INST_TYPE_BLR;
                return true;
            }
            break;
        case 0x02:  /* RET */
            if (op3 == 0) {
                SAFE_STRCPY(result->mnemonic, "ret");
                result->type = INST_TYPE_RET;
                return true;
            }
            break;
        case 0x04:  /* ERET */
            if (op3 == 0 && rn == 31) {
                SAFE_STRCPY(result->mnemonic, "eret");
                result->type = INST_TYPE_RET;
                return true;
            }
            break;
        case 0x05:  /* DRPS */
            if (op3 == 0 && rn == 31) {
                SAFE_STRCPY(result->mnemonic, "drps");
                result->type = INST_TYPE_RET;
                return true;
            }
            break;
    }
    
    return false;
}

/**
 * 解析系统指令 - NOP/HINT/MRS等
 * 编码：1101010100|L|op0|op1|CRn|CRm|op2|Rt
 * mask: 0xFFC00000, value: 0xD5000000
 */
static bool decode_system(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t op0 = BITS(inst, 19, 20);
    uint8_t op1 = BITS(inst, 16, 18);
    uint8_t crn = BITS(inst, 12, 15);
    uint8_t crm = BITS(inst, 8, 11);
    uint8_t op2 = BITS(inst, 5, 7);
    uint8_t rt = BITS(inst, 0, 4);
    uint8_t L = BIT(inst, 21);
    
    /* NOP和HINT指令 */
    if (op0 == 0 && op1 == 3 && crn == 2 && rt == 31) {
        if (crm == 0) {
            static const char *hint_names[] = {
                "nop", "yield", "wfe", "wfi", "sev", "sevl"
            };
            if (op2 < 6) {
                SAFE_STRCPY(result->mnemonic, hint_names[op2]);
                result->type = INST_TYPE_NOP;
                return true;
            }
        }
    }

    /* MRS指令 */
    if (L == 1 && rt != 31) {
        result->rd = rt;
        result->rd_type = REG_TYPE_X;
        result->is_64bit = true;
        result->has_imm = false;
        SAFE_STRCPY(result->mnemonic, "mrs");
        result->type = INST_TYPE_MRS;
        return true;
    }
    
    return false;
}

/* ========== 分支指令解码表 ========== */

const decode_entry_t branch_decode_table[] = {
    /* 无条件分支（立即数）- B/BL: bits[30:26] = 00101 */
    DECODE_ENTRY(0x7C000000, 0x14000000, decode_uncond_branch_imm),
    
    /* 比较并分支 - CBZ/CBNZ: bits[30:25] = 011010 */
    DECODE_ENTRY(0x7E000000, 0x34000000, decode_compare_branch),
    
    /* 测试位并分支 - TBZ/TBNZ: bits[30:25] = 011011 */
    DECODE_ENTRY(0x7E000000, 0x36000000, decode_test_branch),
    
    /* 条件分支 - B.cond: bits[31:25] = 0101010, bit[4] = 0 */
    DECODE_ENTRY(0xFF000010, 0x54000000, decode_cond_branch_imm),
    
    /* 无条件分支（寄存器）- BR/BLR/RET: bits[31:25] = 1101011 */
    DECODE_ENTRY(0xFE000000, 0xD6000000, decode_uncond_branch_reg),
    
    /* 系统指令 - NOP/MRS等: bits[31:22] = 1101010100 */
    DECODE_ENTRY(0xFFC00000, 0xD5000000, decode_system),
};

const size_t branch_decode_table_size = ARRAY_SIZE(branch_decode_table);

/* ========== 主分支指令解析函数（表驱动） ========== */

bool decode_branch(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    return decode_with_table(branch_decode_table, branch_decode_table_size,
                            inst, addr, result);
}
