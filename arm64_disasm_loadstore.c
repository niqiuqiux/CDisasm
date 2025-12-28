/**
 * ARM64反汇编器 - 加载/存储指令解析（表驱动版本）
 * 支持LDR/STR/LDP/STP及其变体
 */

#include "arm64_disasm.h"
#include "arm64_decode_table.h"
#include <string.h>
#include <stdio.h>

/* ========== 加载/存储解码辅助结构 ========== */

/* 加载/存储指令信息表 */
typedef struct {
    uint8_t size_opc;       /* (size << 2) | opc */
    const char *mnemonic;
    inst_type_t type;
    reg_type_t reg_type;
    bool is_64bit;
} ls_info_t;

/* 通用寄存器加载/存储信息表 */
static const ls_info_t gpr_ls_info[] = {
    { 0x00, "strb",  INST_TYPE_STRB,  REG_TYPE_W, false },
    { 0x01, "ldrb",  INST_TYPE_LDRB,  REG_TYPE_W, false },
    { 0x02, "ldrsb", INST_TYPE_LDRSB, REG_TYPE_X, true  },
    { 0x03, "ldrsb", INST_TYPE_LDRSB, REG_TYPE_W, false },
    { 0x04, "strh",  INST_TYPE_STRH,  REG_TYPE_W, false },
    { 0x05, "ldrh",  INST_TYPE_LDRH,  REG_TYPE_W, false },
    { 0x06, "ldrsh", INST_TYPE_LDRSH, REG_TYPE_X, true  },
    { 0x07, "ldrsh", INST_TYPE_LDRSH, REG_TYPE_W, false },
    { 0x08, "str",   INST_TYPE_STR,   REG_TYPE_W, false },
    { 0x09, "ldr",   INST_TYPE_LDR,   REG_TYPE_W, false },
    { 0x0A, "ldrsw", INST_TYPE_LDRSW, REG_TYPE_X, true  },
    { 0x0C, "str",   INST_TYPE_STR,   REG_TYPE_X, true  },
    { 0x0D, "ldr",   INST_TYPE_LDR,   REG_TYPE_X, true  },
};

/* 查找GPR加载/存储信息 */
static const ls_info_t* find_gpr_ls_info(uint8_t size_opc) {
    for (size_t i = 0; i < ARRAY_SIZE(gpr_ls_info); i++) {
        if (gpr_ls_info[i].size_opc == size_opc) {
            return &gpr_ls_info[i];
        }
    }
    return NULL;
}

/* ========== 加载/存储解码函数 ========== */

/**
 * 解析加载/存储寄存器（无符号偏移）
 * 编码：size|111|V|01|imm12|Rn|Rt
 * mask: 0x3B000000, value: 0x39000000
 */
static bool decode_ls_unsigned_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t size = BITS(inst, 30, 31);
    uint8_t V = BIT(inst, 26);
    uint8_t opc = BITS(inst, 22, 23);
    uint16_t imm12 = BITS(inst, 10, 21);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rt = BITS(inst, 0, 4);
    
    result->rn = rn;
    result->rd = rt;
    result->rn_type = (rn == 31) ? REG_TYPE_SP : REG_TYPE_X;
    result->addr_mode = ADDR_MODE_IMM_UNSIGNED;
    result->has_imm = true;
    
    if (V == 0) {
        /* 通用寄存器 */
        uint8_t size_opc = (size << 2) | opc;
        const ls_info_t *info = find_gpr_ls_info(size_opc);
        if (!info) return false;
        
        result->imm = (int64_t)imm12 << size;
        SAFE_STRCPY(result->mnemonic, info->mnemonic);
        result->type = info->type;
        result->rd_type = info->reg_type;
        result->is_64bit = info->is_64bit;
    } else {
        /* SIMD/FP寄存器 */
        result->imm = (int64_t)imm12 << size;
        
        static const reg_type_t simd_types[] = { REG_TYPE_B, REG_TYPE_H, REG_TYPE_S, REG_TYPE_D };
        if (size > 3) return false;
        result->rd_type = simd_types[size];
        
        if (opc == 0) {
            SAFE_STRCPY(result->mnemonic, "str");
            result->type = INST_TYPE_STR;
        } else if (opc == 1) {
            SAFE_STRCPY(result->mnemonic, "ldr");
            result->type = INST_TYPE_LDR;
        } else {
            return false;
        }
    }
    
    return true;
}

/**
 * 解析加载/存储寄存器（寄存器偏移）
 * 编码：size|111|V|00|1|Rm|option|S|10|Rn|Rt
 * mask: 0x3B200C00, value: 0x38200800
 */
static bool decode_ls_reg_offset(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t size = BITS(inst, 30, 31);
    uint8_t V = BIT(inst, 26);
    uint8_t opc = BITS(inst, 22, 23);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t option = BITS(inst, 13, 15);
    uint8_t S = BIT(inst, 12);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rt = BITS(inst, 0, 4);
    
    result->rn = rn;
    result->rd = rt;
    result->rm = rm;
    result->rn_type = (rn == 31) ? REG_TYPE_SP : REG_TYPE_X;
    result->has_imm = false;
    
    result->extend_type = (extend_t)option;
    result->shift_amount = S ? size : 0;
    
    result->rm_type = (option == EXTEND_UXTX || option == EXTEND_SXTX) ? REG_TYPE_X : REG_TYPE_W;
    result->addr_mode = (option == EXTEND_LSL || option == EXTEND_UXTX) ? 
                        ADDR_MODE_REG_OFFSET : ADDR_MODE_REG_EXTEND;
    
    if (V == 0) {
        uint8_t size_opc = (size << 2) | opc;
        const ls_info_t *info = find_gpr_ls_info(size_opc);
        if (!info) return false;
        
        SAFE_STRCPY(result->mnemonic, info->mnemonic);
        result->type = info->type;
        result->rd_type = info->reg_type;
        result->is_64bit = info->is_64bit;
    } else {
        static const reg_type_t simd_types[] = { REG_TYPE_B, REG_TYPE_H, REG_TYPE_S, REG_TYPE_D };
        if (size > 3) return false;
        result->rd_type = simd_types[size];
        
        if (opc == 0) {
            SAFE_STRCPY(result->mnemonic, "str");
            result->type = INST_TYPE_STR;
        } else if (opc == 1) {
            SAFE_STRCPY(result->mnemonic, "ldr");
            result->type = INST_TYPE_LDR;
        } else {
            return false;
        }
    }
    
    return true;
}

/**
 * 解析加载/存储（未缩放立即数/预索引/后索引）
 * 编码：size|111|V|00|0|imm9|idx|Rn|Rt
 * mask: 0x3B200000, value: 0x38000000
 */
static bool decode_ls_unscaled_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t size = BITS(inst, 30, 31);
    uint8_t V = BIT(inst, 26);
    uint8_t opc = BITS(inst, 22, 23);
    int16_t imm9 = BITS(inst, 12, 20);
    uint8_t idx = BITS(inst, 10, 11);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rt = BITS(inst, 0, 4);
    
    result->imm = SIGN_EXTEND(imm9, 9);
    result->rn = rn;
    result->rd = rt;
    result->rn_type = (rn == 31) ? REG_TYPE_SP : REG_TYPE_X;
    result->has_imm = true;
    
    /* 寻址模式 */
    switch (idx) {
        case 0: result->addr_mode = ADDR_MODE_IMM_SIGNED; break;
        case 1: result->addr_mode = ADDR_MODE_POST_INDEX; break;
        case 2: return false;
        case 3: result->addr_mode = ADDR_MODE_PRE_INDEX; break;
    }
    
    if (V == 0) {
        uint8_t size_opc = (size << 2) | opc;
        
        /* 使用静态表映射 */
        static const struct {
            uint8_t size_opc;
            const char *base_name;
            const char *unscaled_name;
            inst_type_t type;
            reg_type_t reg_type;
            bool is_64bit;
        } unscaled_info[] = {
            { 0x00, "strb",  "sturb",  INST_TYPE_STRB,  REG_TYPE_W, false },
            { 0x01, "ldrb",  "ldurb",  INST_TYPE_LDRB,  REG_TYPE_W, false },
            { 0x02, "ldrsb", "ldursb", INST_TYPE_LDRSB, REG_TYPE_X, true  },
            { 0x03, "ldrsb", "ldursb", INST_TYPE_LDRSB, REG_TYPE_W, false },
            { 0x04, "strh",  "sturh",  INST_TYPE_STRH,  REG_TYPE_W, false },
            { 0x05, "ldrh",  "ldurh",  INST_TYPE_LDRH,  REG_TYPE_W, false },
            { 0x06, "ldrsh", "ldursh", INST_TYPE_LDRSH, REG_TYPE_X, true  },
            { 0x07, "ldrsh", "ldursh", INST_TYPE_LDRSH, REG_TYPE_W, false },
            { 0x08, "str",   "stur",   INST_TYPE_STR,   REG_TYPE_W, false },
            { 0x09, "ldr",   "ldur",   INST_TYPE_LDR,   REG_TYPE_W, false },
            { 0x0A, "ldrsw", "ldursw", INST_TYPE_LDRSW, REG_TYPE_X, true  },
            { 0x0C, "str",   "stur",   INST_TYPE_STR,   REG_TYPE_X, true  },
            { 0x0D, "ldr",   "ldur",   INST_TYPE_LDR,   REG_TYPE_X, true  },
        };
        
        for (size_t i = 0; i < ARRAY_SIZE(unscaled_info); i++) {
            if (unscaled_info[i].size_opc == size_opc) {
                SAFE_STRCPY(result->mnemonic, 
                           (idx == 0) ? unscaled_info[i].unscaled_name : unscaled_info[i].base_name);
                result->type = unscaled_info[i].type;
                result->rd_type = unscaled_info[i].reg_type;
                result->is_64bit = unscaled_info[i].is_64bit;
                return true;
            }
        }
        return false;
    } else {
        static const reg_type_t simd_types[] = { REG_TYPE_B, REG_TYPE_H, REG_TYPE_S, REG_TYPE_D };
        if (size > 3) return false;
        result->rd_type = simd_types[size];
        
        if (opc == 0) {
            SAFE_STRCPY(result->mnemonic, (idx == 0) ? "stur" : "str");
            result->type = INST_TYPE_STR;
        } else if (opc == 1) {
            SAFE_STRCPY(result->mnemonic, (idx == 0) ? "ldur" : "ldr");
            result->type = INST_TYPE_LDR;
        } else {
            return false;
        }
    }
    
    return true;
}

/**
 * 解析加载/存储对（LDP/STP）
 * 编码：opc|101|V|idx|L|imm7|Rt2|Rn|Rt
 * mask: 0x3A000000, value: 0x28000000
 */
static bool decode_ls_pair(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t opc = BITS(inst, 30, 31);
    uint8_t V = BIT(inst, 26);
    uint8_t idx = BITS(inst, 23, 24);
    uint8_t L = BIT(inst, 22);
    int8_t imm7 = BITS(inst, 15, 21);
    uint8_t rt2 = BITS(inst, 10, 14);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rt = BITS(inst, 0, 4);
    
    result->rd = rt;
    result->rt2 = rt2;
    result->rn = rn;
    result->rn_type = (rn == 31) ? REG_TYPE_SP : REG_TYPE_X;
    result->has_imm = true;
    
    /* 寻址模式 */
    switch (idx) {
        case 1: result->addr_mode = ADDR_MODE_POST_INDEX; break;
        case 2: result->addr_mode = ADDR_MODE_IMM_SIGNED; break;
        case 3: result->addr_mode = ADDR_MODE_PRE_INDEX; break;
        default: return false;
    }
    
    if (V == 0) {
        /* 通用寄存器对 */
        if (opc == 0x00) {
            result->imm = SIGN_EXTEND(imm7, 7) << 2;
            result->rd_type = REG_TYPE_W;
            SAFE_STRCPY(result->mnemonic, L ? "ldp" : "stp");
            result->type = L ? INST_TYPE_LDP : INST_TYPE_STP;
        } else if (opc == 0x01) {
            if (!L) return false;
            result->imm = SIGN_EXTEND(imm7, 7) << 2;
            result->rd_type = REG_TYPE_X;
            result->is_64bit = true;
            SAFE_STRCPY(result->mnemonic, "ldpsw");
            result->type = INST_TYPE_LDP;
        } else if (opc == 0x02) {
            result->imm = SIGN_EXTEND(imm7, 7) << 3;
            result->rd_type = REG_TYPE_X;
            result->is_64bit = true;
            SAFE_STRCPY(result->mnemonic, L ? "ldp" : "stp");
            result->type = L ? INST_TYPE_LDP : INST_TYPE_STP;
        } else {
            return false;
        }
    } else {
        /* SIMD/FP寄存器对 */
        static const struct { uint8_t shift; reg_type_t type; } simd_pair_info[] = {
            { 2, REG_TYPE_S }, { 3, REG_TYPE_D }, { 4, REG_TYPE_Q }
        };
        
        if (opc > 2) return false;
        result->imm = SIGN_EXTEND(imm7, 7) << simd_pair_info[opc].shift;
        result->rd_type = simd_pair_info[opc].type;
        SAFE_STRCPY(result->mnemonic, L ? "ldp" : "stp");
        result->type = L ? INST_TYPE_LDP : INST_TYPE_STP;
    }
    
    return true;
}

/**
 * 解析加载字面量（LDR literal）
 * 编码：opc|011|V|00|imm19|Rt
 * mask: 0x3B000000, value: 0x18000000
 */
static bool decode_load_literal(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t opc = BITS(inst, 30, 31);
    uint8_t V = BIT(inst, 26);
    int32_t imm19 = BITS(inst, 5, 23);
    uint8_t rt = BITS(inst, 0, 4);
    
    result->imm = SIGN_EXTEND(imm19, 19) << 2;
    result->rd = rt;
    result->has_imm = true;
    result->addr_mode = ADDR_MODE_LITERAL;
    
    SAFE_STRCPY(result->mnemonic, "ldr");
    result->type = INST_TYPE_LDR;
    
    if (V == 0) {
        static const struct { reg_type_t type; bool is_64bit; const char *name; } gpr_literal[] = {
            { REG_TYPE_W, false, "ldr"   },
            { REG_TYPE_X, true,  "ldr"   },
            { REG_TYPE_X, true,  "ldrsw" },
        };
        
        if (opc > 2) return false;
        result->rd_type = gpr_literal[opc].type;
        result->is_64bit = gpr_literal[opc].is_64bit;
        SAFE_STRCPY(result->mnemonic, gpr_literal[opc].name);
        if (opc == 2) result->type = INST_TYPE_LDRSW;
    } else {
        static const reg_type_t simd_literal[] = { REG_TYPE_S, REG_TYPE_D, REG_TYPE_Q };
        if (opc > 2) return false;
        result->rd_type = simd_literal[opc];
    }
    
    return true;
}

/* ========== 原子操作指令 ========== */

/**
 * 解析独占加载/存储指令 - LDXR/STXR/LDAXR/STLXR/LDAR/STLR
 * 编码：size|001000|o2|L|o1|Rs|o0|Rt2|Rn|Rt
 * mask: 0x3F000000, value: 0x08000000
 */
static bool decode_load_store_exclusive(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t size = BITS(inst, 30, 31);
    uint8_t o2 = BIT(inst, 23);
    uint8_t L = BIT(inst, 22);
    uint8_t o1 = BIT(inst, 21);
    uint8_t rs = BITS(inst, 16, 20);
    uint8_t o0 = BIT(inst, 15);
    uint8_t rt2 = BITS(inst, 10, 14);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rt = BITS(inst, 0, 4);
    
    result->rd = rt;
    result->rn = rn;
    result->rm = rs;  /* 用于STXR的状态寄存器 */
    result->rt2 = rt2;
    result->rn_type = (rn == 31) ? REG_TYPE_SP : REG_TYPE_X;
    result->has_imm = false;
    result->addr_mode = ADDR_MODE_IMM_UNSIGNED;
    
    /* 确定寄存器大小 */
    result->is_64bit = (size == 3);
    result->rd_type = result->is_64bit ? REG_TYPE_X : REG_TYPE_W;
    result->rm_type = REG_TYPE_W;  /* 状态寄存器总是W */
    
    /* 获取/释放语义 */
    result->is_acquire = o0;
    result->is_release = o1;
    
    /* 根据编码确定指令类型 */
    if (o2 == 0) {
        /* 独占加载/存储 */
        if (L == 1) {
            /* 加载 */
            if (o1 == 0 && o0 == 0) {
                SAFE_STRCPY(result->mnemonic, "ldxr");
                result->type = INST_TYPE_LDXR;
            } else if (o1 == 0 && o0 == 1) {
                SAFE_STRCPY(result->mnemonic, "ldaxr");
                result->type = INST_TYPE_LDAXR;
            } else if (o1 == 1 && o0 == 0) {
                /* LDXP - 独占加载对 */
                SAFE_STRCPY(result->mnemonic, "ldxp");
                result->type = INST_TYPE_LDXR;
            } else {
                /* LDAXP */
                SAFE_STRCPY(result->mnemonic, "ldaxp");
                result->type = INST_TYPE_LDAXR;
            }
        } else {
            /* 存储 */
            if (o1 == 0 && o0 == 0) {
                SAFE_STRCPY(result->mnemonic, "stxr");
                result->type = INST_TYPE_STXR;
            } else if (o1 == 0 && o0 == 1) {
                SAFE_STRCPY(result->mnemonic, "stlxr");
                result->type = INST_TYPE_STLXR;
            } else if (o1 == 1 && o0 == 0) {
                /* STXP */
                SAFE_STRCPY(result->mnemonic, "stxp");
                result->type = INST_TYPE_STXR;
            } else {
                /* STLXP */
                SAFE_STRCPY(result->mnemonic, "stlxp");
                result->type = INST_TYPE_STLXR;
            }
        }
    } else {
        /* 加载-获取/存储-释放（非独占） */
        if (L == 1) {
            if (o0 == 1) {
                SAFE_STRCPY(result->mnemonic, "ldar");
                result->type = INST_TYPE_LDAR;
            } else {
                /* LDLAR (ARMv8.1) */
                SAFE_STRCPY(result->mnemonic, "ldlar");
                result->type = INST_TYPE_LDAR;
            }
        } else {
            if (o0 == 1) {
                SAFE_STRCPY(result->mnemonic, "stlr");
                result->type = INST_TYPE_STLR;
            } else {
                /* STLLR (ARMv8.1) */
                SAFE_STRCPY(result->mnemonic, "stllr");
                result->type = INST_TYPE_STLR;
            }
        }
    }
    
    /* 根据size添加后缀 */
    if (size == 0) {
        /* 字节 */
        size_t len = strlen(result->mnemonic);
        if (len < sizeof(result->mnemonic) - 1) {
            result->mnemonic[len] = 'b';
            result->mnemonic[len + 1] = '\0';
        }
        result->rd_type = REG_TYPE_W;
    } else if (size == 1) {
        /* 半字 */
        size_t len = strlen(result->mnemonic);
        if (len < sizeof(result->mnemonic) - 1) {
            result->mnemonic[len] = 'h';
            result->mnemonic[len + 1] = '\0';
        }
        result->rd_type = REG_TYPE_W;
    }
    
    return true;
}

/**
 * 解析原子内存操作指令 - LDADD/LDCLR/LDEOR/LDSET/SWP/CAS等 (ARMv8.1)
 * 编码：size|111|V|00|A|R|1|Rs|o3|opc|00|Rn|Rt
 * mask: 0x3B200C00, value: 0x38200000
 */
static bool decode_atomic_memory_ops(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t size = BITS(inst, 30, 31);
    uint8_t V = BIT(inst, 26);
    uint8_t A = BIT(inst, 23);
    uint8_t R = BIT(inst, 22);
    uint8_t rs = BITS(inst, 16, 20);
    uint8_t o3 = BIT(inst, 15);
    uint8_t opc = BITS(inst, 12, 14);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rt = BITS(inst, 0, 4);
    
    if (V != 0) return false;  /* V必须为0 */
    
    result->rd = rt;
    result->rn = rn;
    result->rm = rs;
    result->rn_type = (rn == 31) ? REG_TYPE_SP : REG_TYPE_X;
    result->has_imm = false;
    result->addr_mode = ADDR_MODE_IMM_UNSIGNED;
    result->is_acquire = A;
    result->is_release = R;
    
    result->is_64bit = (size == 3);
    result->rd_type = result->is_64bit ? REG_TYPE_X : REG_TYPE_W;
    result->rm_type = result->rd_type;
    
    /* 构建助记符后缀 */
    char suffix[4] = "";
    if (A && R) {
        strcpy(suffix, "al");
    } else if (A) {
        strcpy(suffix, "a");
    } else if (R) {
        strcpy(suffix, "l");
    }
    
    /* 大小后缀 */
    char size_suffix[2] = "";
    if (size == 0) {
        strcpy(size_suffix, "b");
        result->rd_type = REG_TYPE_W;
        result->rm_type = REG_TYPE_W;
    } else if (size == 1) {
        strcpy(size_suffix, "h");
        result->rd_type = REG_TYPE_W;
        result->rm_type = REG_TYPE_W;
    }
    
    /* 根据o3和opc确定操作 */
    if (o3 == 0) {
        static const struct {
            const char *name;
            inst_type_t type;
        } atomic_ops[] = {
            { "ldadd",  INST_TYPE_LDADD  },  /* 000 */
            { "ldclr",  INST_TYPE_LDCLR  },  /* 001 */
            { "ldeor",  INST_TYPE_LDEOR  },  /* 010 */
            { "ldset",  INST_TYPE_LDSET  },  /* 011 */
            { "ldsmax", INST_TYPE_LDSMAX },  /* 100 */
            { "ldsmin", INST_TYPE_LDSMIN },  /* 101 */
            { "ldumax", INST_TYPE_LDUMAX },  /* 110 */
            { "ldumin", INST_TYPE_LDUMIN },  /* 111 */
        };
        
        snprintf(result->mnemonic, sizeof(result->mnemonic), "%s%s%s",
                atomic_ops[opc].name, suffix, size_suffix);
        result->type = atomic_ops[opc].type;
    } else {
        /* o3 == 1: SWP */
        snprintf(result->mnemonic, sizeof(result->mnemonic), "swp%s%s",
                suffix, size_suffix);
        result->type = INST_TYPE_SWP;
    }
    
    return true;
}

/**
 * 解析CAS指令 - 比较并交换 (ARMv8.1)
 * 编码：size|0010001|o1|1|Rs|o0|11111|Rn|Rt
 * mask: 0x3FA07C00, value: 0x08A07C00
 */
static bool decode_cas(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t size = BITS(inst, 30, 31);
    uint8_t o1 = BIT(inst, 22);
    uint8_t rs = BITS(inst, 16, 20);
    uint8_t o0 = BIT(inst, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rt = BITS(inst, 0, 4);
    
    result->rd = rt;
    result->rn = rn;
    result->rm = rs;
    result->rn_type = (rn == 31) ? REG_TYPE_SP : REG_TYPE_X;
    result->has_imm = false;
    result->addr_mode = ADDR_MODE_IMM_UNSIGNED;
    result->is_acquire = o0;
    result->is_release = o1;
    result->type = INST_TYPE_CAS;
    
    result->is_64bit = (size == 3);
    result->rd_type = result->is_64bit ? REG_TYPE_X : REG_TYPE_W;
    result->rm_type = result->rd_type;
    
    /* 构建助记符 */
    char suffix[4] = "";
    if (o0 && o1) {
        strcpy(suffix, "al");
    } else if (o0) {
        strcpy(suffix, "a");
    } else if (o1) {
        strcpy(suffix, "l");
    }
    
    char size_suffix[2] = "";
    if (size == 0) {
        strcpy(size_suffix, "b");
        result->rd_type = REG_TYPE_W;
        result->rm_type = REG_TYPE_W;
    } else if (size == 1) {
        strcpy(size_suffix, "h");
        result->rd_type = REG_TYPE_W;
        result->rm_type = REG_TYPE_W;
    }
    
    snprintf(result->mnemonic, sizeof(result->mnemonic), "cas%s%s", suffix, size_suffix);
    
    return true;
}

/* ========== 加载/存储解码表 ========== */

const decode_entry_t load_store_decode_table[] = {
    /* 独占加载/存储: bits[29:24] = 001000 */
    DECODE_ENTRY(0x3F000000, 0x08000000, decode_load_store_exclusive),
    
    /* CAS指令: bits[29:23] = 0010001, bits[14:10] = 11111 */
    DECODE_ENTRY(0x3FA07C00, 0x08A07C00, decode_cas),
    
    /* 原子内存操作: bits[29:27] = 111, bits[25:24] = 00, bit[21] = 1, bits[11:10] = 00 */
    DECODE_ENTRY(0x3B200C00, 0x38200000, decode_atomic_memory_ops),
    
    /* 加载/存储对: bits[31:30]|101|V|... */
    DECODE_ENTRY(0x3A000000, 0x28000000, decode_ls_pair),
    
    /* 加载字面量: bits[29:27] = 011, bits[25:24] = 00 */
    DECODE_ENTRY(0x3B000000, 0x18000000, decode_load_literal),
    
    /* 无符号立即数偏移: bits[29:27] = 111, bits[25:24] = 01 */
    DECODE_ENTRY(0x3B000000, 0x39000000, decode_ls_unsigned_imm),
    
    /* 寄存器偏移: bits[29:27] = 111, bits[25:24] = 00, bit[21] = 1, bits[11:10] = 10 */
    DECODE_ENTRY(0x3B200C00, 0x38200800, decode_ls_reg_offset),
    
    /* 未缩放立即数/预索引/后索引: bits[29:27] = 111, bits[25:24] = 00, bit[21] = 0 */
    DECODE_ENTRY(0x3B200000, 0x38000000, decode_ls_unscaled_imm),
};

const size_t load_store_decode_table_size = ARRAY_SIZE(load_store_decode_table);

/* ========== 主加载/存储解析函数（表驱动） ========== */

bool decode_load_store(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    return decode_with_table(load_store_decode_table, load_store_decode_table_size,
                            inst, addr, result);
}
