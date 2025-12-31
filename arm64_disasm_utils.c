/**
 * ARM64反汇编器 - 工具函数实现
 * 包含寄存器名称获取、格式化输出等辅助函数
 */

#include "arm64_disasm.h"
#include <stdio.h>
#include <string.h>

/* 寄存器名称表 */
static const char *x_reg_names[] = {
    "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
    "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "fp",  "lr",  "xzr"
};

static const char *w_reg_names[] = {
    "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",
    "w8",  "w9",  "w10", "w11", "w12", "w13", "w14", "w15",
    "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
    "w24", "w25", "w26", "w27", "w28", "w29", "w30", "wzr"
};

/**
 * 获取寄存器名称（表驱动版本）
 */
void get_register_name(uint8_t reg_num, reg_type_t reg_type, char *buffer) {
    if (reg_num > 31) {
        sprintf(buffer, "?%d", reg_num);
        return;
    }
    
    switch (reg_type) {
        case REG_TYPE_X:
            strcpy(buffer, x_reg_names[reg_num]);
            break;
        case REG_TYPE_W:
            strcpy(buffer, w_reg_names[reg_num]);
            break;
        case REG_TYPE_SP:
            strcpy(buffer, "sp");
            break;
        case REG_TYPE_XZR:
            strcpy(buffer, "xzr");
            break;
        case REG_TYPE_WZR:
            strcpy(buffer, "wzr");
            break;
        case REG_TYPE_V:
            sprintf(buffer, "v%d", reg_num);
            break;
        case REG_TYPE_B:
            sprintf(buffer, "b%d", reg_num);
            break;
        case REG_TYPE_H:
            sprintf(buffer, "h%d", reg_num);
            break;
        case REG_TYPE_S:
            sprintf(buffer, "s%d", reg_num);
            break;
        case REG_TYPE_D:
            sprintf(buffer, "d%d", reg_num);
            break;
        case REG_TYPE_Q:
            sprintf(buffer, "q%d", reg_num);
            break;
        default:
            sprintf(buffer, "?%d", reg_num);
            break;
    }
}

/* 扩展类型名称表 */
static const char *extend_names[] = {
    "uxtb", "uxth", "uxtw", "uxtx",
    "sxtb", "sxth", "sxtw", "sxtx",
    "lsl"
};

/**
 * 获取扩展类型名称（表驱动版本）
 */
static const char* get_extend_name(extend_t extend) {
    if (extend <= EXTEND_LSL) {
        return extend_names[extend];
    }
    return "";
}

/**
 * 格式化寄存器操作数
 */
static void format_register_operand(const disasm_inst_t *inst, char *buffer, size_t size, 
                                     uint8_t reg_num, reg_type_t reg_type) {
    char reg_name[16];
    get_register_name(reg_num, reg_type, reg_name);
    
    // 现在完全由解码阶段决定寄存器类型（X/W vs SP/XZR/WZR），
    // 这里不再根据指令类型进行启发式修改，避免将应为XZR/WZR的寄存器误打印为SP。
    snprintf(buffer, size, "%s", reg_name);
}

/**
 * 格式化内存操作数
 */
static void format_memory_operand(const disasm_inst_t *inst, char *buffer, size_t size) {
    char base_reg[16];
    get_register_name(inst->rn, inst->rn_type, base_reg);
    
    // 如果基址寄存器是31，通常是SP
    if (inst->rn == 31) {
        strcpy(base_reg, "sp");
    }
    
    switch (inst->addr_mode) {
        case ADDR_MODE_IMM_UNSIGNED:
        case ADDR_MODE_IMM_SIGNED:
            if (inst->imm == 0) {
                snprintf(buffer, size, "[%s]", base_reg);
            } else {
                snprintf(buffer, size, "[%s, #%lld]", base_reg, (long long)inst->imm);
            }
            break;
            
        case ADDR_MODE_PRE_INDEX:
            snprintf(buffer, size, "[%s, #%lld]!", base_reg, (long long)inst->imm);
            break;
            
        case ADDR_MODE_POST_INDEX:
            snprintf(buffer, size, "[%s], #%lld", base_reg, (long long)inst->imm);
            break;
            
        case ADDR_MODE_REG_OFFSET: {
            char offset_reg[16];
            get_register_name(inst->rm, inst->rm_type, offset_reg);
            snprintf(buffer, size, "[%s, %s]", base_reg, offset_reg);
            break;
        }
            
        case ADDR_MODE_REG_EXTEND: {
            char offset_reg[16];
            get_register_name(inst->rm, inst->rm_type, offset_reg);
            const char *extend_name = get_extend_name(inst->extend_type);
            
            if (inst->shift_amount > 0) {
                snprintf(buffer, size, "[%s, %s, %s #%d]", 
                        base_reg, offset_reg, extend_name, inst->shift_amount);
            } else {
                snprintf(buffer, size, "[%s, %s, %s]", 
                        base_reg, offset_reg, extend_name);
            }
            break;
        }
            
        case ADDR_MODE_LITERAL:
            snprintf(buffer, size, "0x%llx", (unsigned long long)(inst->address + inst->imm));
            break;
            
        default:
            snprintf(buffer, size, "[%s]", base_reg);
            break;
    }
}

typedef struct {
    uint8_t op0;
    uint8_t op1;
    uint8_t crn;
    uint8_t crm;
    uint8_t op2;
    const char *name;
} sys_reg_info_t;

static const sys_reg_info_t system_reg_map[] = {
    {3, 3, 4, 2, 0, "NZCV"},
    {3, 3, 4, 2, 1, "DAIF"},
    {3, 0, 4, 2, 2, "CurrentEL"},
    {3, 0, 4, 2, 0, "SPSel"},
    
    {3, 0, 4, 1, 0, "SP_EL0"},
    {3, 4, 4, 1, 0, "SP_EL1"},
    {3, 6, 4, 1, 0, "SP_EL2"},
    {3, 7, 4, 1, 0, "SP_EL3"},
    
    {3, 0, 4, 0, 0, "SPSR_EL1"},
    {3, 0, 4, 0, 1, "ELR_EL1"},
    {3, 4, 4, 0, 0, "SPSR_EL2"},
    {3, 4, 4, 0, 1, "ELR_EL2"},
    {3, 5, 4, 0, 0, "SPSR_EL12"},
    {3, 5, 4, 0, 1, "ELR_EL12"},
    {3, 6, 4, 0, 0, "SPSR_EL3"},
    {3, 6, 4, 0, 1, "ELR_EL3"},
    
    {3, 3, 13, 0, 2, "TPIDR_EL0"},
    {3, 3, 13, 0, 3, "TPIDRRO_EL0"},
    {3, 3, 13, 0, 5, "TPIDR2_EL0"},
    {3, 0, 13, 0, 4, "TPIDR_EL1"},
    {3, 4, 13, 0, 2, "TPIDR_EL2"},
    {3, 6, 13, 0, 2, "TPIDR_EL3"},
    
    {3, 3, 4, 4, 0, "FPCR"},
    {3, 3, 4, 4, 1, "FPSR"}
};

/**
 * 获取系统寄存器名称（用于MRS解码）
 * 支持的寄存器收录在system_reg_map表中，其余使用通用编码格式。
 */
static const char* get_system_reg_name(uint8_t op0, uint8_t op1,
                                       uint8_t crn, uint8_t crm, uint8_t op2) {
    for (size_t i = 0; i < sizeof(system_reg_map) / sizeof(system_reg_map[0]); i++) {
        const sys_reg_info_t *info = &system_reg_map[i];
        if (info->op0 == op0 && info->op1 == op1 &&
            info->crn == crn && info->crm == crm && info->op2 == op2) {
            return info->name;
        }
    }
    return NULL;
}

/**
 * 将反汇编指令格式化为字符串
 */
void format_instruction(const disasm_inst_t *inst, char *buffer, size_t buffer_size) {
    char operands[256] = {0};
    char reg_dst[16], reg_src1[16], reg_src2[16], reg_t2[16];
    
    // 根据指令类型格式化操作数
    switch (inst->type) {
        // 加载/存储指令
        case INST_TYPE_LDR:
        case INST_TYPE_LDRB:
        case INST_TYPE_LDRH:
        case INST_TYPE_LDRSW:
        case INST_TYPE_LDRSB:
        case INST_TYPE_LDRSH:
        case INST_TYPE_STR:
        case INST_TYPE_STRB:
        case INST_TYPE_STRH: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            char mem_operand[128];
            format_memory_operand(inst, mem_operand, sizeof(mem_operand));
            snprintf(operands, sizeof(operands), "%s, %s", reg_dst, mem_operand);
            break;
        }
        
        // 加载/存储对指令
        case INST_TYPE_LDP:
        case INST_TYPE_STP: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_t2, sizeof(reg_t2), inst->rt2, inst->rd_type);
            char mem_operand[128];
            format_memory_operand(inst, mem_operand, sizeof(mem_operand));
            snprintf(operands, sizeof(operands), "%s, %s, %s", reg_dst, reg_t2, mem_operand);
            break;
        }
        
        // MOV立即数指令
        case INST_TYPE_MOVZ:
        case INST_TYPE_MOVN:
        case INST_TYPE_MOVK: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            if (inst->shift_amount > 0) {
                snprintf(operands, sizeof(operands), "%s, #0x%llx, lsl #%d", 
                        reg_dst, (unsigned long long)inst->imm, inst->shift_amount);
            } else {
                snprintf(operands, sizeof(operands), "%s, #0x%llx", 
                        reg_dst, (unsigned long long)inst->imm);
            }
            break;
        }
        
        // MOV寄存器指令
        case INST_TYPE_MOV: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            if (inst->has_imm) {
                snprintf(operands, sizeof(operands), "%s, #0x%llx", 
                        reg_dst, (unsigned long long)inst->imm);
            } else {
                format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rm, inst->rm_type);
                snprintf(operands, sizeof(operands), "%s, %s", reg_dst, reg_src1);
            }
            break;
        }
        
        // 算术指令（带立即数）
        case INST_TYPE_ADD:
        case INST_TYPE_SUB:
        case INST_TYPE_ADDS:
        case INST_TYPE_SUBS: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            
            if (inst->has_imm) {
                if (inst->shift_amount > 0) {
                    snprintf(operands, sizeof(operands), "%s, %s, #0x%llx, lsl #%d", 
                            reg_dst, reg_src1, (unsigned long long)inst->imm, inst->shift_amount);
                } else {
                    snprintf(operands, sizeof(operands), "%s, %s, #0x%llx", 
                            reg_dst, reg_src1, (unsigned long long)inst->imm);
                }
            } else {
                format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
                if (inst->shift_amount > 0) {
                    const char *shift_name = get_extend_name(inst->extend_type);
                    snprintf(operands, sizeof(operands), "%s, %s, %s, %s #%d", 
                            reg_dst, reg_src1, reg_src2, shift_name, inst->shift_amount);
                } else {
                    snprintf(operands, sizeof(operands), "%s, %s, %s", 
                            reg_dst, reg_src1, reg_src2);
                }
            }
            break;
        }
        
        // 比较指令
        case INST_TYPE_CMP:
        case INST_TYPE_CMN: {
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            if (inst->has_imm) {
                snprintf(operands, sizeof(operands), "%s, #0x%llx", 
                        reg_src1, (unsigned long long)inst->imm);
            } else {
                format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
                snprintf(operands, sizeof(operands), "%s, %s", reg_src1, reg_src2);
            }
            break;
        }
        
        // ADR/ADRP指令
        case INST_TYPE_ADR:
        case INST_TYPE_ADRP: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            snprintf(operands, sizeof(operands), "%s, 0x%llx", 
                    reg_dst, (unsigned long long)(inst->address + inst->imm));
            break;
        }
        
        // 分支指令
        case INST_TYPE_B:
        case INST_TYPE_BL: {
            snprintf(operands, sizeof(operands), "0x%llx", 
                    (unsigned long long)(inst->address + inst->imm));
            break;
        }
        
        case INST_TYPE_BR:
        case INST_TYPE_BLR:
        case INST_TYPE_RET: {
            if (inst->type == INST_TYPE_RET && inst->rn == 30) {
                // RET默认使用LR
                operands[0] = '\0';
            } else {
                format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
                snprintf(operands, sizeof(operands), "%s", reg_src1);
            }
            break;
        }
        
        case INST_TYPE_CBZ:
        case INST_TYPE_CBNZ: {
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rd, inst->rd_type);
            snprintf(operands, sizeof(operands), "%s, 0x%llx", 
                    reg_src1, (unsigned long long)(inst->address + inst->imm));
            break;
        }
        
        case INST_TYPE_TBZ:
        case INST_TYPE_TBNZ: {
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rd, inst->rd_type);
            snprintf(operands, sizeof(operands), "%s, #%d, 0x%llx", 
                    reg_src1, inst->shift_amount, (unsigned long long)(inst->address + inst->imm));
            break;
        }
        
        // 逻辑指令
        case INST_TYPE_AND:
        case INST_TYPE_ORR:
        case INST_TYPE_EOR: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            
            if (inst->has_imm) {
                snprintf(operands, sizeof(operands), "%s, %s, #0x%llx", 
                        reg_dst, reg_src1, (unsigned long long)inst->imm);
            } else {
                format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
                snprintf(operands, sizeof(operands), "%s, %s, %s", 
                        reg_dst, reg_src1, reg_src2);
            }
            break;
        }
        
        // 移位指令
        case INST_TYPE_LSL:
        case INST_TYPE_LSR:
        case INST_TYPE_ASR: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            if (inst->has_imm) {
                // 检查助记符判断是否为位域操作指令
                if (strcmp(inst->mnemonic, "ubfm") == 0 || 
                    strcmp(inst->mnemonic, "sbfm") == 0 || 
                    strcmp(inst->mnemonic, "bfm") == 0) {
                    // 位域操作：显示immr和imms
                    uint8_t immr = inst->shift_amount;
                    uint8_t imms = inst->imm & 0x3F;
                    snprintf(operands, sizeof(operands), "%s, %s, #%d, #%d", 
                            reg_dst, reg_src1, immr, imms);
                } else {
                    // 普通移位：只显示移位量
                    snprintf(operands, sizeof(operands), "%s, %s, #%d", 
                            reg_dst, reg_src1, inst->shift_amount);
                }
            } else {
                format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
                snprintf(operands, sizeof(operands), "%s, %s, %s", 
                        reg_dst, reg_src1, reg_src2);
            }
            break;
        }
        
        // 乘法指令
        case INST_TYPE_MUL: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
            snprintf(operands, sizeof(operands), "%s, %s, %s", reg_dst, reg_src1, reg_src2);
            break;
        }
        
        // 除法指令
        case INST_TYPE_UDIV:
        case INST_TYPE_SDIV: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
            snprintf(operands, sizeof(operands), "%s, %s, %s", reg_dst, reg_src1, reg_src2);
            break;
        }

        // MRS 系统寄存器读
        case INST_TYPE_MRS: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            uint32_t raw = inst->raw;
            uint8_t op0 = BITS(raw, 19, 20);
            uint8_t op1 = BITS(raw, 16, 18);
            uint8_t crn = BITS(raw, 12, 15);
            uint8_t crm = BITS(raw, 8, 11);
            uint8_t op2 = BITS(raw, 5, 7);
            
            const char *sys_name = get_system_reg_name(op0, op1, crn, crm, op2);
            if (sys_name) {
                snprintf(operands, sizeof(operands), "%s, %s", reg_dst, sys_name);
            } else {
                // 回退到通用编码形式：S<op0>_<op1>_C<crn>_C<crm>_<op2>
                snprintf(operands, sizeof(operands), "%s, S%u_%u_C%u_C%u_%u",
                         reg_dst, op0, op1, crn, crm, op2);
            }
            break;
        }
        
        // 条件选择指令
        case INST_TYPE_CSEL:
        case INST_TYPE_CSINC:
        case INST_TYPE_CSINV:
        case INST_TYPE_CSNEG: {
            static const char *cond_names[] = {
                "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
            };
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
            snprintf(operands, sizeof(operands), "%s, %s, %s, %s",
                    reg_dst, reg_src1, reg_src2, cond_names[inst->cond & 0xF]);
            break;
        }
        
        // 条件选择别名（单寄存器形式）
        case INST_TYPE_CSET:
        case INST_TYPE_CSETM: {
            static const char *cond_names[] = {
                "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
            };
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            snprintf(operands, sizeof(operands), "%s, %s",
                    reg_dst, cond_names[inst->cond & 0xF]);
            break;
        }
        
        // 条件递增/取反/取负
        case INST_TYPE_CINC:
        case INST_TYPE_CINV:
        case INST_TYPE_CNEG: {
            static const char *cond_names[] = {
                "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
            };
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            snprintf(operands, sizeof(operands), "%s, %s, %s",
                    reg_dst, reg_src1, cond_names[inst->cond & 0xF]);
            break;
        }
        
        // 位操作指令（1源）
        case INST_TYPE_CLZ:
        case INST_TYPE_CLS:
        case INST_TYPE_RBIT:
        case INST_TYPE_REV:
        case INST_TYPE_REV16:
        case INST_TYPE_REV32: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            snprintf(operands, sizeof(operands), "%s, %s", reg_dst, reg_src1);
            break;
        }
        
        // EXTR/ROR指令
        case INST_TYPE_EXTR:
        case INST_TYPE_ROR: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            if (inst->type == INST_TYPE_ROR) {
                snprintf(operands, sizeof(operands), "%s, %s, #%lld",
                        reg_dst, reg_src1, (long long)inst->imm);
            } else {
                format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
                snprintf(operands, sizeof(operands), "%s, %s, %s, #%lld",
                        reg_dst, reg_src1, reg_src2, (long long)inst->imm);
            }
            break;
        }
        
        // 独占加载指令
        case INST_TYPE_LDXR:
        case INST_TYPE_LDAXR:
        case INST_TYPE_LDAR: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            char base_reg[16];
            get_register_name(inst->rn, inst->rn_type, base_reg);
            snprintf(operands, sizeof(operands), "%s, [%s]", reg_dst, base_reg);
            break;
        }
        
        // 独占存储指令
        case INST_TYPE_STXR:
        case INST_TYPE_STLXR: {
            char status_reg[16];
            get_register_name(inst->rm, inst->rm_type, status_reg);
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            char base_reg[16];
            get_register_name(inst->rn, inst->rn_type, base_reg);
            snprintf(operands, sizeof(operands), "%s, %s, [%s]", status_reg, reg_dst, base_reg);
            break;
        }
        
        // 存储-释放指令
        case INST_TYPE_STLR: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            char base_reg[16];
            get_register_name(inst->rn, inst->rn_type, base_reg);
            snprintf(operands, sizeof(operands), "%s, [%s]", reg_dst, base_reg);
            break;
        }
        
        // 原子操作指令
        case INST_TYPE_LDADD:
        case INST_TYPE_LDCLR:
        case INST_TYPE_LDEOR:
        case INST_TYPE_LDSET:
        case INST_TYPE_LDSMAX:
        case INST_TYPE_LDSMIN:
        case INST_TYPE_LDUMAX:
        case INST_TYPE_LDUMIN:
        case INST_TYPE_SWP: {
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rm, inst->rm_type);
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            char base_reg[16];
            get_register_name(inst->rn, inst->rn_type, base_reg);
            snprintf(operands, sizeof(operands), "%s, %s, [%s]", reg_src1, reg_dst, base_reg);
            break;
        }
        
        // CAS指令
        case INST_TYPE_CAS: {
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rm, inst->rm_type);
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            char base_reg[16];
            get_register_name(inst->rn, inst->rn_type, base_reg);
            snprintf(operands, sizeof(operands), "%s, %s, [%s]", reg_src1, reg_dst, base_reg);
            break;
        }
        
        case INST_TYPE_NOP:
            operands[0] = '\0';
            break;
        
        /* 浮点指令格式化 */
        case INST_TYPE_FMOV:
        case INST_TYPE_FABS:
        case INST_TYPE_FNEG:
        case INST_TYPE_FSQRT:
        case INST_TYPE_FCVT:
        case INST_TYPE_FRINT: {
            char fp_dst[16], fp_src[16];
            get_register_name(inst->rd, inst->rd_type, fp_dst);
            if (inst->has_imm && strcmp(inst->mnemonic, "fmov") == 0) {
                /* FMOV立即数 */
                snprintf(operands, sizeof(operands), "%s, #%lld", fp_dst, (long long)inst->imm);
            } else {
                get_register_name(inst->rn, inst->rn_type, fp_src);
                snprintf(operands, sizeof(operands), "%s, %s", fp_dst, fp_src);
            }
            break;
        }
        
        case INST_TYPE_FADD:
        case INST_TYPE_FSUB:
        case INST_TYPE_FMUL:
        case INST_TYPE_FDIV:
        case INST_TYPE_FMAX:
        case INST_TYPE_FMIN: {
            char fp_dst[16], fp_src1[16], fp_src2[16];
            get_register_name(inst->rd, inst->rd_type, fp_dst);
            get_register_name(inst->rn, inst->rn_type, fp_src1);
            get_register_name(inst->rm, inst->rm_type, fp_src2);
            snprintf(operands, sizeof(operands), "%s, %s, %s", fp_dst, fp_src1, fp_src2);
            break;
        }
        
        case INST_TYPE_FMADD:
        case INST_TYPE_FMSUB:
        case INST_TYPE_FNMADD:
        case INST_TYPE_FNMSUB: {
            char fp_dst[16], fp_src1[16], fp_src2[16], fp_src3[16];
            get_register_name(inst->rd, inst->rd_type, fp_dst);
            get_register_name(inst->rn, inst->rn_type, fp_src1);
            get_register_name(inst->rm, inst->rm_type, fp_src2);
            get_register_name(inst->ra, inst->rd_type, fp_src3);
            snprintf(operands, sizeof(operands), "%s, %s, %s, %s", fp_dst, fp_src1, fp_src2, fp_src3);
            break;
        }
        
        case INST_TYPE_FCMP:
        case INST_TYPE_FCMPE: {
            char fp_src1[16], fp_src2[16];
            get_register_name(inst->rn, inst->rn_type, fp_src1);
            if (inst->has_imm) {
                snprintf(operands, sizeof(operands), "%s, #0.0", fp_src1);
            } else {
                get_register_name(inst->rm, inst->rm_type, fp_src2);
                snprintf(operands, sizeof(operands), "%s, %s", fp_src1, fp_src2);
            }
            break;
        }
        
        case INST_TYPE_FCCMP: {
            static const char *cond_names[] = {
                "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
            };
            char fp_src1[16], fp_src2[16];
            get_register_name(inst->rn, inst->rn_type, fp_src1);
            get_register_name(inst->rm, inst->rm_type, fp_src2);
            snprintf(operands, sizeof(operands), "%s, %s, #%lld, %s",
                    fp_src1, fp_src2, (long long)inst->imm, cond_names[inst->cond & 0xF]);
            break;
        }
        
        case INST_TYPE_FCSEL: {
            static const char *cond_names[] = {
                "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
            };
            char fp_dst[16], fp_src1[16], fp_src2[16];
            get_register_name(inst->rd, inst->rd_type, fp_dst);
            get_register_name(inst->rn, inst->rn_type, fp_src1);
            get_register_name(inst->rm, inst->rm_type, fp_src2);
            snprintf(operands, sizeof(operands), "%s, %s, %s, %s",
                    fp_dst, fp_src1, fp_src2, cond_names[inst->cond & 0xF]);
            break;
        }
        
        case INST_TYPE_FCVTZS:
        case INST_TYPE_FCVTZU:
        case INST_TYPE_SCVTF:
        case INST_TYPE_UCVTF: {
            char dst[16], src[16];
            get_register_name(inst->rd, inst->rd_type, dst);
            get_register_name(inst->rn, inst->rn_type, src);
            snprintf(operands, sizeof(operands), "%s, %s", dst, src);
            break;
        }
            
        default:
            snprintf(operands, sizeof(operands), "; raw=0x%08x", inst->raw);
            break;
    }
    
    // 组合最终输出
    if (operands[0] != '\0') {
        snprintf(buffer, buffer_size, "%-8s %s", inst->mnemonic, operands);
    } else {
        snprintf(buffer, buffer_size, "%s", inst->mnemonic);
    }
}

/**
 * 打印单条指令
 */
void print_instruction(const disasm_inst_t *inst) {
    char buffer[256];
    format_instruction(inst, buffer, sizeof(buffer));
    printf("0x%016llx:  %08x  %s\n", 
           (unsigned long long)inst->address, inst->raw, buffer);
}

