/**
 * ARM64反汇编器 - 主解析入口（表驱动版本）
 * 整合所有指令解析模块，使用统一的表驱动架构
 */

#include "arm64_disasm.h"
#include "arm64_decode_table.h"
#include <stdio.h>
#include <string.h>

/* ========== 解码表辅助函数 ========== */

/**
 * 在解码表中查找匹配的条目并执行解码
 */
bool decode_with_table(const decode_entry_t *table, size_t table_size,
                       uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    for (size_t i = 0; i < table_size; i++) {
        if ((inst & table[i].mask) == table[i].value) {
            if (table[i].decoder(inst, addr, result)) {
                return true;
            }
        }
    }
    return false;
}

/* ========== 顶层解码分发函数 ========== */

/**
 * 分发到数据处理（立即数）解码
 */
static bool dispatch_data_proc_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    return decode_data_proc_imm(inst, addr, result);
}

/**
 * 分发到数据处理（寄存器）解码
 */
static bool dispatch_data_proc_reg(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    return decode_data_proc_reg(inst, addr, result);
}

/**
 * 分发到分支指令解码
 */
static bool dispatch_branch(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    return decode_branch(inst, addr, result);
}

/**
 * 分发到加载/存储解码
 */
static bool dispatch_load_store(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    return decode_load_store(inst, addr, result);
}

/* ========== 顶层解码表 ========== */

/*
 * ARM64 顶层指令分类（基于 bits[28:25]）：
 * 
 * 0000-0011: 保留/加载存储
 * 0100: 加载/存储
 * 0101: 数据处理（寄存器）/ 分支
 * 0110: 加载/存储
 * 0111: 加载/存储 / SIMD
 * 1000-1001: 数据处理（立即数）
 * 1010-1011: 分支 / 数据处理（寄存器）
 * 1100-1110: 加载/存储
 * 1111: 加载/存储 / SIMD
 */

const decode_entry_t top_level_decode_table[] = {
    /* 数据处理（立即数）: bits[28:26] = 100 */
    DECODE_ENTRY_NAMED(0x1C000000, 0x10000000, dispatch_data_proc_imm, "data_proc_imm"),
    
    /* 分支、异常、系统: bits[28:26] = 101 */
    DECODE_ENTRY_NAMED(0x1C000000, 0x14000000, dispatch_branch, "branch"),
    
    /* 加载/存储: bits[27] = 1, bits[25] = 0 */
    DECODE_ENTRY_NAMED(0x0A000000, 0x08000000, dispatch_load_store, "load_store_1"),
    
    /* 加载/存储: bits[28:26] = 110 或 111 */
    DECODE_ENTRY_NAMED(0x1C000000, 0x18000000, dispatch_load_store, "load_store_2"),
    
    /* 数据处理（寄存器）: bits[28:25] = 0101 或 1101 */
    DECODE_ENTRY_NAMED(0x0E000000, 0x0A000000, dispatch_data_proc_reg, "data_proc_reg"),
};

const size_t top_level_decode_table_size = ARRAY_SIZE(top_level_decode_table);

/* ========== 初始化函数 ========== */

/**
 * 初始化反汇编指令结构
 */
static void init_disasm_inst(disasm_inst_t *inst, uint32_t raw, uint64_t address) {
    memset(inst, 0, sizeof(disasm_inst_t));
    inst->raw = raw;
    inst->address = address;
    inst->type = INST_TYPE_UNKNOWN;
    SAFE_STRCPY(inst->mnemonic, "unknown");
}

/* ========== 主反汇编函数 ========== */

/**
 * 反汇编单条ARM64指令（表驱动版本）
 */
bool disassemble_arm64(uint32_t raw_inst, uint64_t address, disasm_inst_t *inst) {
    if (!inst) {
        return false;
    }
    
    init_disasm_inst(inst, raw_inst, address);
    
    /* 使用顶层解码表进行分发 */
    if (decode_with_table(top_level_decode_table, top_level_decode_table_size,
                         raw_inst, address, inst)) {
        return true;
    }
    
    /* 如果顶层表未匹配，尝试直接调用各子解码器 */
    /* 这是为了处理一些边界情况 */
    if (decode_branch(raw_inst, address, inst)) return true;
    if (decode_data_proc_imm(raw_inst, address, inst)) return true;
    if (decode_data_proc_reg(raw_inst, address, inst)) return true;
    if (decode_load_store(raw_inst, address, inst)) return true;
    
    return (inst->type != INST_TYPE_UNKNOWN);
}

/* ========== 批量反汇编 ========== */

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

/* ========== 辅助函数 ========== */

/**
 * 获取分支指令的目标地址
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
    if (!inst) return false;
    
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
    if (!inst) return false;
    
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
    
    /* 辅助宏：添加寄存器（避免重复） */
    #define ADD_REG(reg, type) do { \
        if (*count < max_count && ((reg) < 31 || (type) == REG_TYPE_SP)) { \
            bool found = false; \
            for (size_t i = 0; i < *count; i++) { \
                if (regs[i] == (reg)) { found = true; break; } \
            } \
            if (!found) regs[(*count)++] = (reg); \
        } \
    } while(0)
    
    ADD_REG(inst->rd, inst->rd_type);
    ADD_REG(inst->rn, inst->rn_type);
    ADD_REG(inst->rm, inst->rm_type);
    ADD_REG(inst->rt2, inst->rd_type);
    
    #undef ADD_REG
}

/**
 * 获取指令的立即数值
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
    if (!inst) return;
    
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
    
    uint64_t target;
    if (get_branch_target(inst, &target)) {
        printf("分支目标:   0x%016llx\n", (unsigned long long)target);
    }
    
    printf("====================\n");
}
