/**
 * ARM64反汇编器 - 分支指令解析
 * 包括B、BL、BR、BLR、RET、CBZ、CBNZ等
 */

#include "arm64_disasm.h"
#include <stdio.h>
#include <string.h>

/**
 * 解析无条件分支（立即数）
 * B和BL指令
 * 编码格式：op|00101|imm26
 */
static bool decode_unconditional_branch_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t op = BIT(inst, 31);
    int32_t imm26 = BITS(inst, 0, 25);
    
    // 符号扩展并左移2位（指令对齐）
    result->imm = SIGN_EXTEND(imm26, 26) << 2;
    result->has_imm = true;
    
    if (op == 0) {
        // B - 分支
        strcpy(result->mnemonic, "b");
        result->type = INST_TYPE_B;
    } else {
        // BL - 带链接分支（调用函数）
        strcpy(result->mnemonic, "bl");
        result->type = INST_TYPE_BL;
    }
    
    return true;
}

/**
 * 解析条件分支（立即数）
 * B.cond指令
 * 编码格式：0101010|0|imm19|0|cond
 */
static bool decode_conditional_branch_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    int32_t imm19 = BITS(inst, 5, 23);
    uint8_t cond = BITS(inst, 0, 3);
    
    // 符号扩展并左移2位
    result->imm = SIGN_EXTEND(imm19, 19) << 2;
    result->has_imm = true;
    result->type = INST_TYPE_B;
    
    // 条件码
    const char *cond_names[] = {
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
 * 解析比较并分支
 * CBZ和CBNZ指令
 * 编码格式：sf|011010|op|imm19|Rt
 */
static bool decode_compare_and_branch(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
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
        // CBZ - 为零则分支
        strcpy(result->mnemonic, "cbz");
        result->type = INST_TYPE_CBZ;
    } else {
        // CBNZ - 非零则分支
        strcpy(result->mnemonic, "cbnz");
        result->type = INST_TYPE_CBNZ;
    }
    
    return true;
}

/**
 * 解析测试位并分支
 * TBZ和TBNZ指令
 * 编码格式：b5|011011|op|b40|imm14|Rt
 */
static bool decode_test_and_branch(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t b5 = BIT(inst, 31);
    uint8_t op = BIT(inst, 24);
    uint8_t b40 = BITS(inst, 19, 23);
    int16_t imm14 = BITS(inst, 5, 18);
    uint8_t rt = BITS(inst, 0, 4);
    
    // 组合位编号
    uint8_t bit_pos = (b5 << 5) | b40;
    
    result->rd = rt;
    result->rd_type = (bit_pos < 32) ? REG_TYPE_W : REG_TYPE_X;
    result->imm = SIGN_EXTEND(imm14, 14) << 2;
    result->shift_amount = bit_pos;  // 用于存储测试的位位置
    result->has_imm = true;
    result->is_64bit = (bit_pos >= 32);
    
    if (op == 0) {
        // TBZ - 测试位为零则分支
        strcpy(result->mnemonic, "tbz");
        result->type = INST_TYPE_TBZ;
    } else {
        // TBNZ - 测试位非零则分支
        strcpy(result->mnemonic, "tbnz");
        result->type = INST_TYPE_TBNZ;
    }
    
    return true;
}

/**
 * 解析无条件分支（寄存器）
 * BR、BLR、RET指令
 * 编码格式：1101011|opc|op2|op3|Rn|op4
 */
static bool decode_unconditional_branch_reg(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t opc = BITS(inst, 21, 24);
    uint8_t op2 = BITS(inst, 16, 20);
    uint8_t op3 = BITS(inst, 10, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t op4 = BITS(inst, 0, 4);
    
    result->rn = rn;
    result->rn_type = REG_TYPE_X;
    result->has_imm = false;
    result->is_64bit = true;
    
    // 检查固定字段
    if (op2 != 31 || op4 != 0) {  // 0b11111 == 31, 0b00000 == 0
        return false;
    }
    
    switch (opc) {
        case 0x00:  // BR (0b0000)
            if (op3 == 0) {
                strcpy(result->mnemonic, "br");
                result->type = INST_TYPE_BR;
                return true;
            }
            break;
            
        case 0x01:  // BLR (0b0001)
            if (op3 == 0) {
                strcpy(result->mnemonic, "blr");
                result->type = INST_TYPE_BLR;
                return true;
            }
            break;
            
        case 0x02:  // RET (0b0010)
            if (op3 == 0) {
                strcpy(result->mnemonic, "ret");
                result->type = INST_TYPE_RET;
                return true;
            }
            break;
            
        case 0x04:  // ERET (0b0100)
            if (op3 == 0 && rn == 31) {
                strcpy(result->mnemonic, "eret");
                result->type = INST_TYPE_RET;  // 使用RET类型
                return true;
            }
            break;
            
        case 0x05:  // DRPS (0b0101)
            if (op3 == 0 && rn == 31) {
                strcpy(result->mnemonic, "drps");
                result->type = INST_TYPE_RET;  // 使用RET类型
                return true;
            }
            break;
            
        default:
            break;
    }
    
    return false;
}

/**
 * 解析系统指令
 * 包括NOP、HINT等
 */
static bool decode_system(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t op0 = BITS(inst, 19, 20);  // op0占据bits[20:19]
    uint8_t op1 = BITS(inst, 16, 18);
    uint8_t crn = BITS(inst, 12, 15);
    uint8_t crm = BITS(inst, 8, 11);
    uint8_t op2 = BITS(inst, 5, 7);
    uint8_t rt = BITS(inst, 0, 4);
    uint8_t L = BIT(inst, 21);         // L=1 表示 MRS，L=0 表示 MSR
    
    // NOP和HINT指令
    if (op0 == 0 && op1 == 3 && crn == 2 && rt == 31) {  // 0b000, 0b011, 0b0010, 0b11111
        if (crm == 0) {  // 0b0000
            switch (op2) {
                case 0:  // 0b000
                    strcpy(result->mnemonic, "nop");
                    result->type = INST_TYPE_NOP;
                    return true;
                case 1:  // 0b001
                    strcpy(result->mnemonic, "yield");
                    result->type = INST_TYPE_NOP;
                    return true;
                case 2:  // 0b010
                    strcpy(result->mnemonic, "wfe");
                    result->type = INST_TYPE_NOP;
                    return true;
                case 3:  // 0b011
                    strcpy(result->mnemonic, "wfi");
                    result->type = INST_TYPE_NOP;
                    return true;
                case 4:  // 0b100
                    strcpy(result->mnemonic, "sev");
                    result->type = INST_TYPE_NOP;
                    return true;
                case 5:  // 0b101
                    strcpy(result->mnemonic, "sevl");
                    result->type = INST_TYPE_NOP;
                    return true;
                default:
                    break;
            }
        }
    }

    // MRS 指令（从系统寄存器读到通用寄存器）
    // 此处只做通用解码：识别为 MRS 并保留系统寄存器编码字段，
    // 具体系统寄存器名称在格式化阶段通过编码字段构造。
    if (L == 1 && rt != 31) {
        result->rd = rt;
        result->rd_type = REG_TYPE_X;
        result->is_64bit = true;
        result->has_imm = false;
        strcpy(result->mnemonic, "mrs");
        result->type = INST_TYPE_MRS;
        return true;
    }
    
    return false;
}

/**
 * 主分支指令解析函数
 */
bool decode_branch(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t op0 = BITS(inst, 29, 31);       // bits[31:29]
    uint8_t op1 = BITS(inst, 26, 31);       // bits[31:26] (6位)
    uint8_t op1_5bits = BITS(inst, 25, 29); // bits[29:25] (5位)
    uint8_t op2_6bits = BITS(inst, 25, 30); // bits[30:25] (6位)
    uint8_t op2_5bits = BITS(inst, 26, 30); // bits[30:26] (5位)
    
    // 无条件分支（立即数）- bits[31] = 0/1, bits[30:26] = 00101
    if (op2_5bits == 0x05) {  // bits[30:26] == 0b00101
        return decode_unconditional_branch_imm(inst, addr, result);
    }
    
    // 比较并分支 - bits[31] = 0/1, bits[30:25] = 011010
    if (op2_6bits == 0x1A) {  // bits[30:25] == 0b011010
        return decode_compare_and_branch(inst, addr, result);
    }
    
    // 测试位并分支 - bits[31] = 0/1, bits[30:25] = 011011
    if (op2_6bits == 0x1B) {  // bits[30:25] == 0b011011
        return decode_test_and_branch(inst, addr, result);
    }
    
    // 条件分支（立即数）- bits[31:25] = 0101010, bit[4] = 0
    if (BITS(inst, 25, 31) == 0x2A && BIT(inst, 4) == 0) {  // bits[31:25] == 0b0101010
        return decode_conditional_branch_imm(inst, addr, result);
    }
    
    // 无条件分支（寄存器）- bits[31:25] = 1101011
    if (BITS(inst, 25, 31) == 0x6B) {  // bits[31:25] == 0b1101011
        return decode_unconditional_branch_reg(inst, addr, result);
    }
    
    // 系统指令（包括NOP）- bits[31:22] = 1101010100
    if (BITS(inst, 22, 31) == 0x354) {  // bits[31:22] == 0b1101010100
        return decode_system(inst, addr, result);
    }
    
    return false;
}

