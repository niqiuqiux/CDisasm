/**
 * ARM64反汇编器 - 主解析入口
 * 整合所有指令解析模块
 */

#include "arm64_disasm.h"
#include <stdio.h>
#include <string.h>

/**
 * 初始化反汇编指令结构
 */
static void init_disasm_inst(disasm_inst_t *inst, uint32_t raw, uint64_t address) {
    memset(inst, 0, sizeof(disasm_inst_t));
    inst->raw = raw;
    inst->address = address;
    inst->type = INST_TYPE_UNKNOWN;
    strcpy(inst->mnemonic, "unknown");
}

/**
 * 反汇编单条ARM64指令
 */
bool disassemble_arm64(uint32_t raw_inst, uint64_t address, disasm_inst_t *inst) {
    if (!inst) {
        return false;
    }
    
    // 初始化结构
    init_disasm_inst(inst, raw_inst, address);
    
    // 提取主要操作码字段
    uint8_t op0 = BITS(raw_inst, 25, 28);  // bits[28:25]
    uint8_t op1 = BITS(raw_inst, 29, 31);  // bits[31:29]
    
    // 根据op0和op1分发到不同的解码函数
    // ARM64顶层指令分类基于bits[28:25]和bits[31:29]
    switch (op0) {
        case 0x0:  // 0b0000
        case 0x1:  // 0b0001
        case 0x2:  // 0b0010
        case 0x3:  // 0b0011
            // 可能是加载/存储指令
            if (decode_load_store(raw_inst, address, inst)) {
                return true;
            }
            break;
            
        case 0x8:  // 0b1000
        case 0x9:  // 0b1001
            // 数据处理（立即数）
            if (decode_data_proc_imm(raw_inst, address, inst)) {
                return true;
            }
            break;
            
        case 0xA:  // 0b1010
        case 0xB:  // 0b1011
            // 需要更精确的判断
            // 如果bits[31:30]=10且bits[28:25]=1010，则是数据处理（寄存器）
            if (op0 == 0xA && (raw_inst & 0xC0000000) == 0x80000000) {
                // bits[31:30] = 10
                if (decode_data_proc_reg(raw_inst, address, inst)) {
                    return true;
                }
            }
            // 分支、异常、系统指令
            if (decode_branch(raw_inst, address, inst)) {
                return true;
            }
            break;
            
        case 0x4:  // 0b0100
        case 0x6:  // 0b0110
        case 0xC:  // 0b1100
        case 0xE:  // 0b1110
            // 加载/存储指令
            if (decode_load_store(raw_inst, address, inst)) {
                return true;
            }
            break;
            
        case 0x5:  // 0b0101
        case 0xD:  // 0b1101
            // 先尝试分支指令（CBZ/CBNZ/TBZ/TBNZ可能在这里）
            if (decode_branch(raw_inst, address, inst)) {
                return true;
            }
            // 数据处理（寄存器）
            if (decode_data_proc_reg(raw_inst, address, inst)) {
                return true;
            }
            break;
            
        case 0x7:  // 0b0111
        case 0xF:  // 0b1111
            // 先尝试加载/存储（可能是SIMD/FP加载存储）
            if (decode_load_store(raw_inst, address, inst)) {
                return true;
            }
            // 数据处理（SIMD和FP）
            // 暂不实现SIMD/FP指令的完整解码
            break;
            
        default:
            break;
    }
    
    // 如果所有解码都失败，保持为UNKNOWN
    return (inst->type != INST_TYPE_UNKNOWN);
}

/**
 * 批量反汇编
 */
void disassemble_block(const uint32_t *code, size_t count, uint64_t start_addr) {
    if (!code || count == 0) {
        return;
    }
    
    printf("=== ARM64 反汇编 ===\n");
    printf("起始地址: 0x%016llx\n", (unsigned long long)start_addr);
    printf("指令数量: %zu\n\n", count);
    printf("%-18s  %-10s  %s\n", "地址", "机器码", "指令");
    printf("--------------------------------------------------\n");
    
    for (size_t i = 0; i < count; i++) {
        disasm_inst_t inst;
        uint64_t addr = start_addr + (i * 4);
        
        if (disassemble_arm64(code[i], addr, &inst)) {
            char buffer[256];
            format_instruction(&inst, buffer, sizeof(buffer));
            printf("0x%016llx:  %08x  %s\n", 
                   (unsigned long long)addr, code[i], buffer);
        } else {
            printf("0x%016llx:  %08x  <未知指令>\n", 
                   (unsigned long long)addr, code[i]);
        }
    }
    
    printf("\n=== 反汇编完成 ===\n");
}

/**
 * 从内存中反汇编指定范围
 */
void disassemble_from_memory(const void *start_addr, size_t byte_count) {
    if (!start_addr || byte_count == 0 || byte_count % 4 != 0) {
        fprintf(stderr, "错误：无效的地址或大小（大小必须是4的倍数）\n");
        return;
    }
    
    const uint32_t *code = (const uint32_t *)start_addr;
    size_t inst_count = byte_count / 4;
    
    disassemble_block(code, inst_count, (uint64_t)start_addr);
}

/**
 * 获取指令的目标地址（用于分支指令）
 */
bool get_branch_target(const disasm_inst_t *inst, uint64_t *target) {
    if (!inst || !target) {
        return false;
    }
    
    switch (inst->type) {
        case INST_TYPE_B:
        case INST_TYPE_BL:
        case INST_TYPE_CBZ:
        case INST_TYPE_CBNZ:
        case INST_TYPE_TBZ:
        case INST_TYPE_TBNZ:
            *target = inst->address + inst->imm;
            return true;
            
        case INST_TYPE_ADR:
        case INST_TYPE_ADRP:
            *target = inst->address + inst->imm;
            return true;
            
        default:
            return false;
    }
}

/**
 * 判断指令是否为分支指令
 */
bool is_branch_instruction(const disasm_inst_t *inst) {
    if (!inst) {
        return false;
    }
    
    switch (inst->type) {
        case INST_TYPE_B:
        case INST_TYPE_BL:
        case INST_TYPE_BR:
        case INST_TYPE_BLR:
        case INST_TYPE_RET:
        case INST_TYPE_CBZ:
        case INST_TYPE_CBNZ:
        case INST_TYPE_TBZ:
        case INST_TYPE_TBNZ:
            return true;
        default:
            return false;
    }
}

/**
 * 判断指令是否为加载/存储指令
 */
bool is_load_store_instruction(const disasm_inst_t *inst) {
    if (!inst) {
        return false;
    }
    
    switch (inst->type) {
        case INST_TYPE_LDR:
        case INST_TYPE_LDRB:
        case INST_TYPE_LDRH:
        case INST_TYPE_LDRSW:
        case INST_TYPE_LDRSB:
        case INST_TYPE_LDRSH:
        case INST_TYPE_STR:
        case INST_TYPE_STRB:
        case INST_TYPE_STRH:
        case INST_TYPE_LDP:
        case INST_TYPE_STP:
            return true;
        default:
            return false;
    }
}

/**
 * 提取指令中使用的寄存器
 */
void get_used_registers(const disasm_inst_t *inst, 
                       uint8_t *regs, size_t *count, size_t max_count) {
    if (!inst || !regs || !count || max_count == 0) {
        return;
    }
    
    *count = 0;
    
    // 添加目标寄存器（包括对SP的使用）
    if (*count < max_count) {
        if (inst->rd < 31 || inst->rd_type == REG_TYPE_SP) {
            regs[(*count)++] = inst->rd;
        }
    }
    
    // 添加源寄存器
    if (*count < max_count && (inst->rn < 31 || inst->rn_type == REG_TYPE_SP)) {
        bool already_added = false;
        for (size_t i = 0; i < *count; i++) {
            if (regs[i] == inst->rn) {
                already_added = true;
                break;
            }
        }
        if (!already_added) {
            regs[(*count)++] = inst->rn;
        }
    }
    
    // 添加第二源寄存器
    if (*count < max_count && (inst->rm < 31 || inst->rm_type == REG_TYPE_SP)) {
        bool already_added = false;
        for (size_t i = 0; i < *count; i++) {
            if (regs[i] == inst->rm) {
                already_added = true;
                break;
            }
        }
        if (!already_added) {
            regs[(*count)++] = inst->rm;
        }
    }
    
    // 添加第二目标寄存器（LDP/STP）
    if (*count < max_count && (inst->rt2 < 31 || inst->rd_type == REG_TYPE_SP)) {
        bool already_added = false;
        for (size_t i = 0; i < *count; i++) {
            if (regs[i] == inst->rt2) {
                already_added = true;
                break;
            }
        }
        if (!already_added) {
            regs[(*count)++] = inst->rt2;
        }
    }
}

/**
 * 获取指令的立即数值（如果存在）
 */
bool get_immediate_value(const disasm_inst_t *inst, int64_t *value) {
    if (!inst || !value) {
        return false;
    }
    
    if (inst->has_imm) {
        *value = inst->imm;
        return true;
    }
    
    return false;
}

/**
 * 打印指令的详细信息
 */
void print_instruction_details(const disasm_inst_t *inst) {
    if (!inst) {
        return;
    }
    
    printf("=== 指令详细信息 ===\n");
    printf("地址:       0x%016llx\n", (unsigned long long)inst->address);
    printf("机器码:     0x%08x\n", inst->raw);
    printf("助记符:     %s\n", inst->mnemonic);
    printf("类型:       %d\n", inst->type);
    printf("64位操作:   %s\n", inst->is_64bit ? "是" : "否");
    
    if (inst->rd < 32) {
        char reg_name[16];
        get_register_name(inst->rd, inst->rd_type, reg_name);
        printf("目标寄存器: %s (R%d)\n", reg_name, inst->rd);
    }
    
    if (inst->rn < 32) {
        char reg_name[16];
        get_register_name(inst->rn, inst->rn_type, reg_name);
        printf("源寄存器1:  %s (R%d)\n", reg_name, inst->rn);
    }
    
    if (inst->rm < 32) {
        char reg_name[16];
        get_register_name(inst->rm, inst->rm_type, reg_name);
        printf("源寄存器2:  %s (R%d)\n", reg_name, inst->rm);
    }
    
    if (inst->has_imm) {
        printf("立即数:     %lld (0x%llx)\n", 
               (long long)inst->imm, (unsigned long long)inst->imm);
    }
    
    if (inst->shift_amount > 0) {
        printf("移位量:     %d\n", inst->shift_amount);
    }
    
    if (inst->addr_mode != ADDR_MODE_NONE) {
        printf("寻址模式:   %d\n", inst->addr_mode);
    }
    
    // 如果是分支指令，显示目标地址
    uint64_t target;
    if (get_branch_target(inst, &target)) {
        printf("分支目标:   0x%016llx\n", (unsigned long long)target);
    }
    
    printf("====================\n");
}

