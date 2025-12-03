/**
 * ARM64反汇编器 - 数据处理指令解析
 * 包括MOV、ADD、SUB、逻辑运算等指令
 */

#include "arm64_disasm.h"
#include <string.h>

/**
 * 解析MOV (wide immediate) - MOVZ/MOVN/MOVK
 * 编码格式：sf|opc|100101|hw|imm16|Rd
 */
static bool decode_move_wide_immediate(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t opc = BITS(inst, 29, 30);
    uint8_t hw = BITS(inst, 21, 22);
    uint16_t imm16 = BITS(inst, 5, 20);
    uint8_t rd = BITS(inst, 0, 4);
    
    result->rd = rd;
    result->imm = imm16;
    result->shift_amount = hw * 16;
    result->has_imm = true;
    result->is_64bit = sf;
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    // 检查hw字段有效性
    if (!sf && hw >= 2) {
        return false;  // 32位操作只能使用hw=0或1
    }
    
    switch (opc) {
        case 0x00:  // MOVN - move not (0b00)
            strcpy(result->mnemonic, "movn");
            result->type = INST_TYPE_MOVN;
            break;
        case 0x02:  // MOVZ - move zero (0b10)
            strcpy(result->mnemonic, "movz");
            result->type = INST_TYPE_MOVZ;
            break;
        case 0x03:  // MOVK - move keep (0b11)
            strcpy(result->mnemonic, "movk");
            result->type = INST_TYPE_MOVK;
            break;
        default:
            return false;
    }
    
    return true;
}

/**
 * 解析PC相对地址 - ADR/ADRP
 * 编码格式：op|immlo|10000|immhi|Rd
 */
static bool decode_pc_rel_addressing(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t op = BIT(inst, 31);
    uint8_t immlo = BITS(inst, 29, 30);
    uint32_t immhi = BITS(inst, 5, 23);
    uint8_t rd = BITS(inst, 0, 4);
    
    result->rd = rd;
    result->rd_type = REG_TYPE_X;
    result->has_imm = true;
    result->is_64bit = true;
    
    if (op == 0) {
        // ADR - 地址到寄存器
        int32_t imm21 = (immhi << 2) | immlo;
        result->imm = SIGN_EXTEND(imm21, 21);
        strcpy(result->mnemonic, "adr");
        result->type = INST_TYPE_ADR;
    } else {
        // ADRP - 页地址到寄存器
        int32_t imm21 = (immhi << 2) | immlo;
        result->imm = SIGN_EXTEND(imm21, 21) << 12;  // 页对齐（4KB）
        strcpy(result->mnemonic, "adrp");
        result->type = INST_TYPE_ADRP;
    }
    
    return true;
}

/**
 * 解析加法/减法（立即数）
 * 编码格式：sf|op|S|100010|shift|imm12|Rn|Rd
 */
static bool decode_add_sub_immediate(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t op = BIT(inst, 30);
    uint8_t S = BIT(inst, 29);
    uint8_t shift = BITS(inst, 22, 23);
    uint16_t imm12 = BITS(inst, 10, 21);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    result->rd = rd;
    result->rn = rn;
    result->imm = imm12;
    result->shift_amount = (shift == 1) ? 12 : 0;  // LSL #0 或 LSL #12
    result->has_imm = true;
    result->is_64bit = sf;
    result->set_flags = S;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    if (shift > 1) {
        return false;  // shift只能是0或1
    }
    
    if (op == 0) {
        // ADD
        strcpy(result->mnemonic, S ? "adds" : "add");
        result->type = S ? INST_TYPE_ADDS : INST_TYPE_ADD;
        
        // 特殊情况：MOV (to/from SP)
        if (!S && imm12 == 0 && shift == 0) {
            strcpy(result->mnemonic, "mov");
            result->type = INST_TYPE_MOV;
            result->has_imm = false;
            result->rm = rn;
            result->rm_type = result->rn_type;
        }
    } else {
        // SUB
        strcpy(result->mnemonic, S ? "subs" : "sub");
        result->type = S ? INST_TYPE_SUBS : INST_TYPE_SUB;
    }
    
    // 特殊情况：CMP/CMN (Rd是XZR/WZR)
    if (S && rd == 31) {
        if (op == 1) {
            strcpy(result->mnemonic, "cmp");
            result->type = INST_TYPE_CMP;
        } else {
            strcpy(result->mnemonic, "cmn");
            result->type = INST_TYPE_CMN;
        }
        // 对于设置标志位的别名指令，Rd=31 表示零寄存器而不是SP
        result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    }

    // 对于不设置标志位的加/减指令，Rn/Rd 为 31 时表示对 SP 进行运算
    if (!S) {
        if (rn == 31) {
            result->rn_type = REG_TYPE_SP;
        }
        if (rd == 31) {
            result->rd_type = REG_TYPE_SP;
        }
    }
    
    return true;
}

/**
 * 解析逻辑运算（立即数）
 * 编码格式：sf|opc|100100|N|immr|imms|Rn|Rd
 */
static bool decode_logical_immediate(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t opc = BITS(inst, 29, 30);
    uint8_t N = BIT(inst, 22);
    uint8_t immr = BITS(inst, 16, 21);
    uint8_t imms = BITS(inst, 10, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    // 解码位掩码立即数（这是一个复杂的过程）
    // 简化处理：存储immr和imms的组合
    result->imm = (immr << 6) | imms;
    result->rd = rd;
    result->rn = rn;
    result->has_imm = true;
    result->is_64bit = sf;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    switch (opc) {
        case 0x00:  // AND (0b00)
            strcpy(result->mnemonic, "and");
            result->type = INST_TYPE_AND;
            break;
        case 0x01:  // ORR (0b01)
            strcpy(result->mnemonic, "orr");
            result->type = INST_TYPE_ORR;
            // 特殊情况：MOV (Rn是XZR/WZR)
            if (rn == 31) {
                strcpy(result->mnemonic, "mov");
                result->type = INST_TYPE_MOV;
            }
            break;
        case 0x02:  // EOR (0b10)
            strcpy(result->mnemonic, "eor");
            result->type = INST_TYPE_EOR;
            break;
        case 0x03:  // ANDS (0b11)
            strcpy(result->mnemonic, "ands");
            result->type = INST_TYPE_AND;
            result->set_flags = true;
            // 特殊情况：TST (Rd是XZR/WZR)
            if (rd == 31) {
                strcpy(result->mnemonic, "tst");
            }
            break;
        default:
            return false;
    }
    
    return true;
}

/**
 * 解析加法/减法（寄存器）
 * 编码格式：sf|op|S|01011|shift|0|Rm|imm6|Rn|Rd
 */
static bool decode_add_sub_shifted_register(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
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
    
    // 确定移位类型
    switch (shift) {
        case 0:  // 0b00
            result->extend_type = EXTEND_LSL;
            break;
        case 1:  // 0b01
            result->extend_type = EXTEND_LSL + 1;  // LSR
            break;
        case 2:  // 0b10
            result->extend_type = EXTEND_LSL + 2;  // ASR
            break;
        default:
            return false;
    }
    
    if (op == 0) {
        strcpy(result->mnemonic, S ? "adds" : "add");
        result->type = S ? INST_TYPE_ADDS : INST_TYPE_ADD;
    } else {
        strcpy(result->mnemonic, S ? "subs" : "sub");
        result->type = S ? INST_TYPE_SUBS : INST_TYPE_SUB;
    }
    
    // 特殊情况：CMP/CMN
    if (S && rd == 31) {
        if (op == 1) {
            strcpy(result->mnemonic, "cmp");
            result->type = INST_TYPE_CMP;
        } else {
            strcpy(result->mnemonic, "cmn");
            result->type = INST_TYPE_CMN;
        }
        // Rd=31 时为零寄存器
        result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    }
    
    // 特殊情况：NEG (Rn是XZR/WZR)
    if (op == 1 && rn == 31 && !S) {
        strcpy(result->mnemonic, "neg");
        // 这里语义上使用零寄存器，而不是SP
        result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    }

    // 对于普通的 ADD/SUB（不设置标志位，且不是 NEG 别名），Rn/Rd = 31 代表对 SP 进行运算
    if (!S && !(op == 1 && rn == 31 && rd != 31)) {
        if (rn == 31) {
            result->rn_type = REG_TYPE_SP;
        }
        if (rd == 31) {
            result->rd_type = REG_TYPE_SP;
        }
    }
    
    return true;
}

/**
 * 解析逻辑运算（移位寄存器）
 * 编码格式：sf|opc|01010|shift|N|Rm|imm6|Rn|Rd
 */
static bool decode_logical_shifted_register(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
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
    
    // 确定移位类型
    switch (shift) {
        case 0:  // 0b00
            result->extend_type = EXTEND_LSL;
            break;
        case 1:  // 0b01
            result->extend_type = EXTEND_LSL + 1;  // LSR
            break;
        case 2:  // 0b10
            result->extend_type = EXTEND_LSL + 2;  // ASR
            break;
        case 3:  // 0b11
            result->extend_type = EXTEND_LSL + 3;  // ROR
            break;
    }
    
    // 解码操作
    uint8_t op_code = (opc << 1) | N;
    switch (op_code) {
        case 0x00:  // AND (0b000)
            strcpy(result->mnemonic, "and");
            result->type = INST_TYPE_AND;
            break;
        case 0x01:  // BIC (0b001)
            strcpy(result->mnemonic, "bic");
            result->type = INST_TYPE_AND;  // BIC是AND NOT
            break;
        case 0x02:  // ORR (0b010)
            strcpy(result->mnemonic, "orr");
            result->type = INST_TYPE_ORR;
            // 特殊情况：MOV (Rn是XZR/WZR，无移位)
            if (rn == 31 && imm6 == 0 && shift == 0) {
                strcpy(result->mnemonic, "mov");
                result->type = INST_TYPE_MOV;
            }
            break;
        case 0x03:  // ORN (0b011)
            strcpy(result->mnemonic, "orn");
            result->type = INST_TYPE_ORR;  // ORN是ORR NOT
            // 特殊情况：MVN (Rn是XZR/WZR)
            if (rn == 31) {
                strcpy(result->mnemonic, "mvn");
            }
            break;
        case 0x04:  // EOR (0b100)
            strcpy(result->mnemonic, "eor");
            result->type = INST_TYPE_EOR;
            break;
        case 0x05:  // EON (0b101)
            strcpy(result->mnemonic, "eon");
            result->type = INST_TYPE_EOR;  // EON是EOR NOT
            break;
        case 0x06:  // ANDS (0b110)
            strcpy(result->mnemonic, "ands");
            result->type = INST_TYPE_AND;
            result->set_flags = true;
            // 特殊情况：TST (Rd是XZR/WZR)
            if (rd == 31) {
                strcpy(result->mnemonic, "tst");
            }
            break;
        case 0x07:  // BICS (0b111)
            strcpy(result->mnemonic, "bics");
            result->type = INST_TYPE_AND;
            result->set_flags = true;
            break;
        default:
            return false;
    }
    
    return true;
}

/**
 * 解析数据处理（2源寄存器）
 * 包括乘除法等指令
 */
static bool decode_data_proc_2source(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t S = BIT(inst, 29);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t opcode = BITS(inst, 10, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (S) return false;  // S必须为0
    
    result->rd = rd;
    result->rn = rn;
    result->rm = rm;
    result->has_imm = false;
    result->is_64bit = sf;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rm_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    switch (opcode) {
        case 0x02:  // UDIV (0b000010)
            strcpy(result->mnemonic, "udiv");
            result->type = INST_TYPE_UDIV;
            break;
        case 0x03:  // SDIV (0b000011)
            strcpy(result->mnemonic, "sdiv");
            result->type = INST_TYPE_SDIV;
            break;
        case 0x08:  // LSLV (0b001000)
            strcpy(result->mnemonic, "lsl");
            result->type = INST_TYPE_LSL;
            break;
        case 0x09:  // LSRV (0b001001)
            strcpy(result->mnemonic, "lsr");
            result->type = INST_TYPE_LSR;
            break;
        case 0x0A:  // ASRV (0b001010)
            strcpy(result->mnemonic, "asr");
            result->type = INST_TYPE_ASR;
            break;
        case 0x0B:  // RORV (0b001011)
            strcpy(result->mnemonic, "ror");
            result->type = INST_TYPE_ASR + 1;  // ROR
            break;
        default:
            return false;
    }
    
    return true;
}

/**
 * 解析位域操作指令
 * 编码格式：sf|opc|100110|N|immr|imms|Rn|Rd
 */
static bool decode_bitfield(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t opc = BITS(inst, 29, 30);
    uint8_t N = BIT(inst, 22);
    uint8_t immr = BITS(inst, 16, 21);
    uint8_t imms = BITS(inst, 10, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    // N必须等于sf
    if (N != sf) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->has_imm = true;
    result->is_64bit = sf;
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    // 简化处理：存储immr和imms
    result->imm = (immr << 6) | imms;
    result->shift_amount = immr;
    
    switch (opc) {
        case 0x00:  // SBFM (0b00)
            strcpy(result->mnemonic, "sbfm");
            result->type = INST_TYPE_LSL;  // 使用LSL类型
            // 特殊情况检查（如ASR, SXTB等）
            if (immr != 0 && imms == (sf ? 63 : 31)) {
                strcpy(result->mnemonic, "asr");
                result->type = INST_TYPE_ASR;
            }
            break;
        case 0x01:  // BFM (0b01)
            strcpy(result->mnemonic, "bfm");
            result->type = INST_TYPE_LSL;
            break;
        case 0x02:  // UBFM (0b10)
            strcpy(result->mnemonic, "ubfm");
            result->type = INST_TYPE_LSL;
            // 特殊情况：LSR
            if (imms == (sf ? 63 : 31)) {
                strcpy(result->mnemonic, "lsr");
                result->type = INST_TYPE_LSR;
            }
            // 特殊情况：LSL
            if (immr == 0 && imms < (sf ? 63 : 31)) {
                strcpy(result->mnemonic, "lsl");
                result->type = INST_TYPE_LSL;
            }
            break;
        default:
            return false;
    }
    
    return true;
}

/**
 * 主数据处理指令（立即数）解析函数
 */
bool decode_data_proc_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t op0 = BITS(inst, 23, 25);
    
    switch (op0) {
        case 0:  // 0b000
        case 1:  // 0b001
            // PC相对地址
            return decode_pc_rel_addressing(inst, addr, result);
        case 2:  // 0b010
        case 3:  // 0b011
            // 加法/减法（立即数）
            return decode_add_sub_immediate(inst, addr, result);
        case 4:  // 0b100
            // 逻辑运算（立即数）
            return decode_logical_immediate(inst, addr, result);
        case 5:  // 0b101
            // 移动宽立即数
            return decode_move_wide_immediate(inst, addr, result);
        case 6:  // 0b110
            // 位域操作指令
            return decode_bitfield(inst, addr, result);
        default:
            return false;
    }
}

/**
 * 解析数据处理（3源寄存器）
 * 包括乘法、乘加等指令
 */
static bool decode_data_proc_3source(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t op54 = BITS(inst, 29, 30);
    uint8_t op31 = BITS(inst, 21, 23);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t o0 = BIT(inst, 15);
    uint8_t ra = BITS(inst, 10, 14);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (op54 != 0) return false;  // op54必须为0
    
    result->rd = rd;
    result->rn = rn;
    result->rm = rm;
    result->has_imm = false;
    result->is_64bit = sf;
    
    result->rd_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rn_type = sf ? REG_TYPE_X : REG_TYPE_W;
    result->rm_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    // 根据op31和o0判断指令类型
    uint8_t opcode = (op31 << 1) | o0;
    
    switch (opcode) {
        case 0x00:  // MADD - 0b0000
            if (ra == 31) {
                // MUL是MADD的特殊形式，Ra=XZR/WZR
                strcpy(result->mnemonic, "mul");
                result->type = INST_TYPE_MUL;
            } else {
                strcpy(result->mnemonic, "madd");
                result->type = INST_TYPE_MADD;
            }
            break;
        case 0x01:  // MSUB - 0b0001
            if (ra == 31) {
                // MNEG是MSUB的特殊形式
                strcpy(result->mnemonic, "mneg");
                result->type = INST_TYPE_MSUB;
            } else {
                strcpy(result->mnemonic, "msub");
                result->type = INST_TYPE_MSUB;
            }
            break;
        default:
            return false;
    }
    
    return true;
}

/**
 * 主数据处理指令（寄存器）解析函数
 */
bool decode_data_proc_reg(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t op0 = BIT(inst, 30);
    uint8_t op1 = BIT(inst, 28);
    uint8_t op2 = BITS(inst, 24, 28);  // bits[28:24]
    uint8_t op3 = BITS(inst, 10, 15);
    
    // 数据处理（2源寄存器）- sf 0 S 11010110 Rm opcode 0 Rn Rd
    // bits[30]=0, bits[29]=S, bits[28:21]=11010110
    if (BIT(inst, 30) == 0 && BITS(inst, 21, 28) == 0xD6) {  // bits[28:21] = 0b11010110 (214)
        return decode_data_proc_2source(inst, addr, result);
    }
    
    // 数据处理（3源寄存器）- bits[28:24] = 0b11011 (27)
    if (op1 == 1 && op2 == 0x1B) {
        return decode_data_proc_3source(inst, addr, result);
    }
    
    // 逻辑运算（移位寄存器）- bits[28:24] = 0b01010 (10)
    if (op1 == 0 && op2 == 0x0A) {
        return decode_logical_shifted_register(inst, addr, result);
    }
    
    // 加法/减法（移位寄存器）- bits[28:24] = 0b01011 (11)
    if (op1 == 0 && op2 == 0x0B) {
        return decode_add_sub_shifted_register(inst, addr, result);
    }
    
    return false;
}

