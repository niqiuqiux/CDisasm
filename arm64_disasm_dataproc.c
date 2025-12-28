/**
 * ARM64反汇编器 - 数据处理指令解析（表驱动版本）
 * 包括MOV、ADD、SUB、逻辑运算等指令
 */

#include "arm64_disasm.h"
#include "arm64_decode_table.h"
#include <string.h>

/* ========== 数据处理（立即数）解码函数 ========== */

/**
 * 解析PC相对地址 - ADR/ADRP
 * 编码：op|immlo|10000|immhi|Rd
 * mask: 0x1F000000, value: 0x10000000
 */
static bool decode_pc_rel_addr(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t op = BIT(inst, 31);
    uint8_t immlo = BITS(inst, 29, 30);
    uint32_t immhi = BITS(inst, 5, 23);
    uint8_t rd = BITS(inst, 0, 4);
    
    result->rd = rd;
    result->rd_type = REG_TYPE_X;
    result->has_imm = true;
    result->is_64bit = true;
    
    int32_t imm21 = (immhi << 2) | immlo;
    
    if (op == 0) {
        result->imm = SIGN_EXTEND(imm21, 21);
        SAFE_STRCPY(result->mnemonic, "adr");
        result->type = INST_TYPE_ADR;
    } else {
        result->imm = SIGN_EXTEND(imm21, 21) << 12;
        SAFE_STRCPY(result->mnemonic, "adrp");
        result->type = INST_TYPE_ADRP;
    }
    
    return true;
}

/**
 * 解析加法/减法（立即数）
 * 编码：sf|op|S|100010|shift|imm12|Rn|Rd
 * mask: 0x1F000000, value: 0x11000000
 */
static bool decode_add_sub_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t op = BIT(inst, 30);
    uint8_t S = BIT(inst, 29);
    uint8_t shift = BITS(inst, 22, 23);
    uint16_t imm12 = BITS(inst, 10, 21);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (shift > 1) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->imm = imm12;
    result->shift_amount = (shift == 1) ? 12 : 0;
    result->has_imm = true;
    result->is_64bit = sf;
    result->set_flags = S;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    if (op == 0) {
        SAFE_STRCPY(result->mnemonic, S ? "adds" : "add");
        result->type = S ? INST_TYPE_ADDS : INST_TYPE_ADD;
        
        /* MOV (to/from SP) */
        if (!S && imm12 == 0 && shift == 0) {
            SAFE_STRCPY(result->mnemonic, "mov");
            result->type = INST_TYPE_MOV;
            result->has_imm = false;
            result->rm = rn;
            result->rm_type = result->rn_type;
        }
    } else {
        SAFE_STRCPY(result->mnemonic, S ? "subs" : "sub");
        result->type = S ? INST_TYPE_SUBS : INST_TYPE_SUB;
    }
    
    /* CMP/CMN (Rd是XZR/WZR) */
    if (S && rd == 31) {
        if (op == 1) {
            SAFE_STRCPY(result->mnemonic, "cmp");
            result->type = INST_TYPE_CMP;
        } else {
            SAFE_STRCPY(result->mnemonic, "cmn");
            result->type = INST_TYPE_CMN;
        }
        result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    }

    /* SP处理 */
    if (!S) {
        if (rn == 31) result->rn_type = REG_TYPE_SP;
        if (rd == 31) result->rd_type = REG_TYPE_SP;
    }
    
    return true;
}

/**
 * 解析逻辑运算（立即数）
 * 编码：sf|opc|100100|N|immr|imms|Rn|Rd
 * mask: 0x1F800000, value: 0x12000000
 */
static bool decode_logical_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t opc = BITS(inst, 29, 30);
    /* N字段用于64位模式验证，暂不使用 */
    /* uint8_t N = BIT(inst, 22); */
    uint8_t immr = BITS(inst, 16, 21);
    uint8_t imms = BITS(inst, 10, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    result->imm = (immr << 6) | imms;
    result->rd = rd;
    result->rn = rn;
    result->has_imm = true;
    result->is_64bit = sf;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    switch (opc) {
        case 0x00:
            SAFE_STRCPY(result->mnemonic, "and");
            result->type = INST_TYPE_AND;
            break;
        case 0x01:
            SAFE_STRCPY(result->mnemonic, "orr");
            result->type = INST_TYPE_ORR;
            if (rn == 31) {
                SAFE_STRCPY(result->mnemonic, "mov");
                result->type = INST_TYPE_MOV;
            }
            break;
        case 0x02:
            SAFE_STRCPY(result->mnemonic, "eor");
            result->type = INST_TYPE_EOR;
            break;
        case 0x03:
            SAFE_STRCPY(result->mnemonic, "ands");
            result->type = INST_TYPE_AND;
            result->set_flags = true;
            if (rd == 31) {
                SAFE_STRCPY(result->mnemonic, "tst");
            }
            break;
        default:
            return false;
    }
    
    return true;
}

/**
 * 解析MOV (wide immediate) - MOVZ/MOVN/MOVK
 * 编码：sf|opc|100101|hw|imm16|Rd
 * mask: 0x1F800000, value: 0x12800000
 */
static bool decode_move_wide_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t opc = BITS(inst, 29, 30);
    uint8_t hw = BITS(inst, 21, 22);
    uint16_t imm16 = BITS(inst, 5, 20);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (!sf && hw >= 2) return false;
    
    result->rd = rd;
    result->imm = imm16;
    result->shift_amount = hw * 16;
    result->has_imm = true;
    result->is_64bit = sf;
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    switch (opc) {
        case 0x00:
            SAFE_STRCPY(result->mnemonic, "movn");
            result->type = INST_TYPE_MOVN;
            break;
        case 0x02:
            SAFE_STRCPY(result->mnemonic, "movz");
            result->type = INST_TYPE_MOVZ;
            break;
        case 0x03:
            SAFE_STRCPY(result->mnemonic, "movk");
            result->type = INST_TYPE_MOVK;
            break;
        default:
            return false;
    }
    
    return true;
}

/**
 * 解析位域操作指令
 * 编码：sf|opc|100110|N|immr|imms|Rn|Rd
 * mask: 0x1F800000, value: 0x13000000
 */
static bool decode_bitfield(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t opc = BITS(inst, 29, 30);
    uint8_t N = BIT(inst, 22);
    uint8_t immr = BITS(inst, 16, 21);
    uint8_t imms = BITS(inst, 10, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (N != sf) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->has_imm = true;
    result->is_64bit = sf;
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->imm = (immr << 6) | imms;
    result->shift_amount = immr;
    
    switch (opc) {
        case 0x00:
            SAFE_STRCPY(result->mnemonic, "sbfm");
            result->type = INST_TYPE_LSL;
            if (immr != 0 && imms == (sf ? 63 : 31)) {
                SAFE_STRCPY(result->mnemonic, "asr");
                result->type = INST_TYPE_ASR;
            }
            break;
        case 0x01:
            SAFE_STRCPY(result->mnemonic, "bfm");
            result->type = INST_TYPE_LSL;
            break;
        case 0x02:
            SAFE_STRCPY(result->mnemonic, "ubfm");
            result->type = INST_TYPE_LSL;
            if (imms == (sf ? 63 : 31)) {
                SAFE_STRCPY(result->mnemonic, "lsr");
                result->type = INST_TYPE_LSR;
            }
            if (immr == 0 && imms < (sf ? 63 : 31)) {
                SAFE_STRCPY(result->mnemonic, "lsl");
                result->type = INST_TYPE_LSL;
            }
            break;
        default:
            return false;
    }
    
    return true;
}

/* ========== 数据处理（寄存器）解码函数 ========== */

/**
 * 解析加法/减法（移位寄存器）
 * 编码：sf|op|S|01011|shift|0|Rm|imm6|Rn|Rd
 * mask: 0x1F200000, value: 0x0B000000
 */
static bool decode_add_sub_shifted_reg(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t op = BIT(inst, 30);
    uint8_t S = BIT(inst, 29);
    uint8_t shift = BITS(inst, 22, 23);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t imm6 = BITS(inst, 10, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    result->rd = rd;
    result->rn = rn;
    result->rm = rm;
    result->shift_amount = imm6;
    result->has_imm = false;
    result->is_64bit = sf;
    result->set_flags = S;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rm_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    switch (shift) {
        case 0: result->extend_type = EXTEND_LSL; break;
        case 1: result->extend_type = EXTEND_LSL + 1; break;
        case 2: result->extend_type = EXTEND_LSL + 2; break;
        default: return false;
    }
    
    if (op == 0) {
        SAFE_STRCPY(result->mnemonic, S ? "adds" : "add");
        result->type = S ? INST_TYPE_ADDS : INST_TYPE_ADD;
    } else {
        SAFE_STRCPY(result->mnemonic, S ? "subs" : "sub");
        result->type = S ? INST_TYPE_SUBS : INST_TYPE_SUB;
    }
    
    /* CMP/CMN */
    if (S && rd == 31) {
        SAFE_STRCPY(result->mnemonic, op == 1 ? "cmp" : "cmn");
        result->type = op == 1 ? INST_TYPE_CMP : INST_TYPE_CMN;
        result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    }
    
    /* NEG */
    if (op == 1 && rn == 31 && !S) {
        SAFE_STRCPY(result->mnemonic, "neg");
        result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    }

    /* SP处理 */
    if (!S && !(op == 1 && rn == 31 && rd != 31)) {
        if (rn == 31) result->rn_type = REG_TYPE_SP;
        if (rd == 31) result->rd_type = REG_TYPE_SP;
    }
    
    return true;
}

/**
 * 解析逻辑运算（移位寄存器）
 * 编码：sf|opc|01010|shift|N|Rm|imm6|Rn|Rd
 * mask: 0x1F000000, value: 0x0A000000
 */
static bool decode_logical_shifted_reg(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t opc = BITS(inst, 29, 30);
    uint8_t shift = BITS(inst, 22, 23);
    uint8_t N = BIT(inst, 21);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t imm6 = BITS(inst, 10, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    result->rd = rd;
    result->rn = rn;
    result->rm = rm;
    result->shift_amount = imm6;
    result->has_imm = false;
    result->is_64bit = sf;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rm_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    result->extend_type = EXTEND_LSL + shift;
    
    uint8_t op_code = (opc << 1) | N;
    switch (op_code) {
        case 0x00:
            SAFE_STRCPY(result->mnemonic, "and");
            result->type = INST_TYPE_AND;
            break;
        case 0x01:
            SAFE_STRCPY(result->mnemonic, "bic");
            result->type = INST_TYPE_AND;
            break;
        case 0x02:
            SAFE_STRCPY(result->mnemonic, "orr");
            result->type = INST_TYPE_ORR;
            if (rn == 31 && imm6 == 0 && shift == 0) {
                SAFE_STRCPY(result->mnemonic, "mov");
                result->type = INST_TYPE_MOV;
            }
            break;
        case 0x03:
            SAFE_STRCPY(result->mnemonic, "orn");
            result->type = INST_TYPE_ORR;
            if (rn == 31) {
                SAFE_STRCPY(result->mnemonic, "mvn");
            }
            break;
        case 0x04:
            SAFE_STRCPY(result->mnemonic, "eor");
            result->type = INST_TYPE_EOR;
            break;
        case 0x05:
            SAFE_STRCPY(result->mnemonic, "eon");
            result->type = INST_TYPE_EOR;
            break;
        case 0x06:
            SAFE_STRCPY(result->mnemonic, "ands");
            result->type = INST_TYPE_AND;
            result->set_flags = true;
            if (rd == 31) {
                SAFE_STRCPY(result->mnemonic, "tst");
            }
            break;
        case 0x07:
            SAFE_STRCPY(result->mnemonic, "bics");
            result->type = INST_TYPE_AND;
            result->set_flags = true;
            break;
        default:
            return false;
    }
    
    return true;
}

/**
 * 解析数据处理（2源寄存器）- 乘除法等
 * 编码：sf|0|S|11010110|Rm|opcode|Rn|Rd
 * mask: 0x5FE00000, value: 0x1AC00000
 */
static bool decode_data_proc_2src(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t S = BIT(inst, 29);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t opcode = BITS(inst, 10, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (S) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->rm = rm;
    result->has_imm = false;
    result->is_64bit = sf;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rm_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    switch (opcode) {
        case 0x02:
            SAFE_STRCPY(result->mnemonic, "udiv");
            result->type = INST_TYPE_UDIV;
            break;
        case 0x03:
            SAFE_STRCPY(result->mnemonic, "sdiv");
            result->type = INST_TYPE_SDIV;
            break;
        case 0x08:
            SAFE_STRCPY(result->mnemonic, "lsl");
            result->type = INST_TYPE_LSL;
            break;
        case 0x09:
            SAFE_STRCPY(result->mnemonic, "lsr");
            result->type = INST_TYPE_LSR;
            break;
        case 0x0A:
            SAFE_STRCPY(result->mnemonic, "asr");
            result->type = INST_TYPE_ASR;
            break;
        case 0x0B:
            SAFE_STRCPY(result->mnemonic, "ror");
            result->type = INST_TYPE_ASR + 1;
            break;
        default:
            return false;
    }
    
    return true;
}

/**
 * 解析数据处理（3源寄存器）- 乘加等
 * 编码：sf|op54|11011|op31|Rm|o0|Ra|Rn|Rd
 * mask: 0x1F000000, value: 0x1B000000
 */
static bool decode_data_proc_3src(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t op54 = BITS(inst, 29, 30);
    uint8_t op31 = BITS(inst, 21, 23);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t o0 = BIT(inst, 15);
    uint8_t ra = BITS(inst, 10, 14);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (op54 != 0) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->rm = rm;
    result->ra = ra;
    result->has_imm = false;
    result->is_64bit = sf;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rm_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    uint8_t opcode = (op31 << 1) | o0;
    
    switch (opcode) {
        case 0x00:
            if (ra == 31) {
                SAFE_STRCPY(result->mnemonic, "mul");
                result->type = INST_TYPE_MUL;
            } else {
                SAFE_STRCPY(result->mnemonic, "madd");
                result->type = INST_TYPE_MADD;
            }
            break;
        case 0x01:
            if (ra == 31) {
                SAFE_STRCPY(result->mnemonic, "mneg");
                result->type = INST_TYPE_MSUB;
            } else {
                SAFE_STRCPY(result->mnemonic, "msub");
                result->type = INST_TYPE_MSUB;
            }
            break;
        default:
            return false;
    }
    
    return true;
}

/* ========== 条件选择指令 ========== */

/**
 * 解析条件选择指令 - CSEL/CSINC/CSINV/CSNEG
 * 编码：sf|op|S|11010100|Rm|cond|op2|Rn|Rd
 * op=0, op2=00: CSEL
 * op=0, op2=01: CSINC
 * op=1, op2=00: CSINV
 * op=1, op2=01: CSNEG
 * mask: 0x1FE00000, value: 0x1A800000
 */
static bool decode_cond_select(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t op = BIT(inst, 30);
    uint8_t S = BIT(inst, 29);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t cond = BITS(inst, 12, 15);
    uint8_t op2 = BITS(inst, 10, 11);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (S != 0) return false;
    if (op2 > 1) return false;  /* op2 只能是 0 或 1 */
    
    result->rd = rd;
    result->rn = rn;
    result->rm = rm;
    result->cond = cond;
    result->has_imm = false;
    result->is_64bit = sf;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rm_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    uint8_t opcode = (op << 1) | op2;  /* 修正：只用2位 */
    
    switch (opcode) {
        case 0x00:  /* CSEL: op=0, op2=0 */
            SAFE_STRCPY(result->mnemonic, "csel");
            result->type = INST_TYPE_CSEL;
            break;
        case 0x01:  /* CSINC: op=0, op2=1 */
            /* 别名检查 */
            if (rm == 31 && rn == 31) {
                /* CSET: csinc Rd, XZR, XZR, invert(cond) */
                SAFE_STRCPY(result->mnemonic, "cset");
                result->type = INST_TYPE_CSET;
                result->cond = cond ^ 1;  /* 反转条件 */
            } else if (rm == rn && cond != 14 && cond != 15) {
                /* CINC: csinc Rd, Rn, Rn, invert(cond) */
                SAFE_STRCPY(result->mnemonic, "cinc");
                result->type = INST_TYPE_CINC;
                result->cond = cond ^ 1;
            } else {
                SAFE_STRCPY(result->mnemonic, "csinc");
                result->type = INST_TYPE_CSINC;
            }
            break;
        case 0x02:  /* CSINV: op=1, op2=0 */
            if (rm == 31 && rn == 31) {
                /* CSETM */
                SAFE_STRCPY(result->mnemonic, "csetm");
                result->type = INST_TYPE_CSETM;
                result->cond = cond ^ 1;
            } else if (rm == rn && cond != 14 && cond != 15) {
                /* CINV */
                SAFE_STRCPY(result->mnemonic, "cinv");
                result->type = INST_TYPE_CINV;
                result->cond = cond ^ 1;
            } else {
                SAFE_STRCPY(result->mnemonic, "csinv");
                result->type = INST_TYPE_CSINV;
            }
            break;
        case 0x03:  /* CSNEG: op=1, op2=1 */
            if (rm == rn && cond != 14 && cond != 15) {
                /* CNEG */
                SAFE_STRCPY(result->mnemonic, "cneg");
                result->type = INST_TYPE_CNEG;
                result->cond = cond ^ 1;
            } else {
                SAFE_STRCPY(result->mnemonic, "csneg");
                result->type = INST_TYPE_CSNEG;
            }
            break;
        default:
            return false;
    }
    
    return true;
}

/* ========== 位操作指令 ========== */

/**
 * 解析数据处理（1源寄存器）- CLZ/CLS/RBIT/REV等
 * 编码：sf|1|S|11010110|opcode2|opcode|Rn|Rd
 * mask: 0x5FE00000, value: 0x5AC00000
 */
static bool decode_data_proc_1src(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t S = BIT(inst, 29);
    uint8_t opcode2 = BITS(inst, 16, 20);
    uint8_t opcode = BITS(inst, 10, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (S != 0 || opcode2 != 0) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->has_imm = false;
    result->is_64bit = sf;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    switch (opcode) {
        case 0x00:  /* RBIT */
            SAFE_STRCPY(result->mnemonic, "rbit");
            result->type = INST_TYPE_RBIT;
            break;
        case 0x01:  /* REV16 */
            SAFE_STRCPY(result->mnemonic, "rev16");
            result->type = INST_TYPE_REV16;
            break;
        case 0x02:  /* REV (32-bit) / REV32 (64-bit) */
            if (sf) {
                SAFE_STRCPY(result->mnemonic, "rev32");
                result->type = INST_TYPE_REV32;
            } else {
                SAFE_STRCPY(result->mnemonic, "rev");
                result->type = INST_TYPE_REV;
            }
            break;
        case 0x03:  /* REV (64-bit only) */
            if (!sf) return false;
            SAFE_STRCPY(result->mnemonic, "rev");
            result->type = INST_TYPE_REV;
            break;
        case 0x04:  /* CLZ */
            SAFE_STRCPY(result->mnemonic, "clz");
            result->type = INST_TYPE_CLZ;
            break;
        case 0x05:  /* CLS */
            SAFE_STRCPY(result->mnemonic, "cls");
            result->type = INST_TYPE_CLS;
            break;
        default:
            return false;
    }
    
    return true;
}

/**
 * 解析EXTR指令 - 提取
 * 编码：sf|00|100111|N|0|Rm|imms|Rn|Rd
 * mask: 0x7FA00000, value: 0x13800000
 */
static bool decode_extract(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t N = BIT(inst, 22);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t imms = BITS(inst, 10, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (sf != N) return false;
    if (!sf && imms >= 32) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->rm = rm;
    result->imm = imms;
    result->has_imm = true;
    result->is_64bit = sf;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rm_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    /* ROR别名：当Rn == Rm时 */
    if (rn == rm) {
        SAFE_STRCPY(result->mnemonic, "ror");
        result->type = INST_TYPE_ROR;
    } else {
        SAFE_STRCPY(result->mnemonic, "extr");
        result->type = INST_TYPE_EXTR;
    }
    
    return true;
}

/* ========== 数据处理解码表 ========== */

/* 数据处理（立即数）解码表 */
const decode_entry_t data_proc_imm_decode_table[] = {
    /* PC相对地址 - ADR/ADRP: bits[28:24] = 10000 */
    DECODE_ENTRY(0x1F000000, 0x10000000, decode_pc_rel_addr),
    
    /* 加法/减法（立即数）: bits[28:24] = 1000x */
    DECODE_ENTRY(0x1F000000, 0x11000000, decode_add_sub_imm),
    
    /* 逻辑运算（立即数）: bits[28:23] = 100100 */
    DECODE_ENTRY(0x1F800000, 0x12000000, decode_logical_imm),
    
    /* 移动宽立即数: bits[28:23] = 100101 */
    DECODE_ENTRY(0x1F800000, 0x12800000, decode_move_wide_imm),
    
    /* 位域操作: bits[28:23] = 100110 */
    DECODE_ENTRY(0x1F800000, 0x13000000, decode_bitfield),
    
    /* EXTR提取: bits[30:23] = 00100111 */
    DECODE_ENTRY(0x7FA00000, 0x13800000, decode_extract),
};

const size_t data_proc_imm_decode_table_size = ARRAY_SIZE(data_proc_imm_decode_table);

/* 数据处理（寄存器）解码表 */
const decode_entry_t data_proc_reg_decode_table[] = {
    /* 逻辑运算（移位寄存器）: bits[28:24] = 01010 */
    DECODE_ENTRY(0x1F000000, 0x0A000000, decode_logical_shifted_reg),
    
    /* 加法/减法（移位寄存器）: bits[28:24] = 01011 */
    DECODE_ENTRY(0x1F200000, 0x0B000000, decode_add_sub_shifted_reg),
    
    /* 条件选择: bits[28:21] = 11010100 */
    DECODE_ENTRY(0x1FE00000, 0x1A800000, decode_cond_select),
    
    /* 数据处理（1源寄存器）: bits[30] = 1, bits[28:21] = 11010110 */
    DECODE_ENTRY(0x5FE00000, 0x5AC00000, decode_data_proc_1src),
    
    /* 数据处理（2源寄存器）: bits[30] = 0, bits[28:21] = 11010110 */
    DECODE_ENTRY(0x5FE00000, 0x1AC00000, decode_data_proc_2src),
    
    /* 数据处理（3源寄存器）: bits[28:24] = 11011 */
    DECODE_ENTRY(0x1F000000, 0x1B000000, decode_data_proc_3src),
};

const size_t data_proc_reg_decode_table_size = ARRAY_SIZE(data_proc_reg_decode_table);

/* ========== 主数据处理解析函数（表驱动） ========== */

bool decode_data_proc_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    return decode_with_table(data_proc_imm_decode_table, data_proc_imm_decode_table_size,
                            inst, addr, result);
}

bool decode_data_proc_reg(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    return decode_with_table(data_proc_reg_decode_table, data_proc_reg_decode_table_size,
                            inst, addr, result);
}
