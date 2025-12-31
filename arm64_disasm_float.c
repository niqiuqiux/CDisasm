/**
 * ARM64反汇编器 - 浮点/SIMD指令解析（表驱动版本）
 * 支持标量浮点运算、浮点比较、浮点转换等指令
 */

#include "arm64_disasm.h"
#include "arm64_decode_table.h"
#include <string.h>
#include <stdio.h>

/* ========== 浮点指令类型扩展 ========== */

/* 浮点寄存器大小映射 */
static reg_type_t get_fp_reg_type(uint8_t ftype) {
    switch (ftype) {
        case 0: return REG_TYPE_S;  /* 单精度 */
        case 1: return REG_TYPE_D;  /* 双精度 */
        case 3: return REG_TYPE_H;  /* 半精度 */
        default: return REG_TYPE_S;
    }
}

/* 获取浮点类型名称后缀 */
static const char* get_fp_suffix(uint8_t ftype) {
    switch (ftype) {
        case 0: return "";   /* 单精度无后缀或用s */
        case 1: return "";   /* 双精度无后缀或用d */
        case 3: return "";   /* 半精度 */
        default: return "";
    }
}

/* ========== 浮点数据处理（1源）========== */

/**
 * 解析浮点数据处理（1源）- FMOV/FABS/FNEG/FSQRT等
 * 编码：M|0|S|11110|ftype|1|opcode|10000|Rn|Rd
 * mask: 0x5F207C00, value: 0x1E204000
 */
static bool decode_fp_data_proc_1src(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t M = BIT(inst, 31);
    uint8_t S = BIT(inst, 29);
    uint8_t ftype = BITS(inst, 22, 23);
    uint8_t opcode = BITS(inst, 15, 20);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (M != 0 || S != 0) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->has_imm = false;
    result->rd_type = get_fp_reg_type(ftype);
    result->rn_type = get_fp_reg_type(ftype);
    
    static const struct {
        uint8_t opcode;
        const char *name;
        inst_type_t type;
    } fp_1src_ops[] = {
        { 0x00, "fmov",   INST_TYPE_FMOV  },
        { 0x01, "fabs",   INST_TYPE_FABS  },
        { 0x02, "fneg",   INST_TYPE_FNEG  },
        { 0x03, "fsqrt",  INST_TYPE_FSQRT },
        { 0x04, "fcvt",   INST_TYPE_FCVT  },  /* 转换到其他精度 */
        { 0x05, "fcvt",   INST_TYPE_FCVT  },
        { 0x07, "fcvt",   INST_TYPE_FCVT  },
        { 0x08, "frintn", INST_TYPE_FRINT },  /* 舍入到最近 */
        { 0x09, "frintp", INST_TYPE_FRINT },  /* 舍入到正无穷 */
        { 0x0A, "frintm", INST_TYPE_FRINT },  /* 舍入到负无穷 */
        { 0x0B, "frintz", INST_TYPE_FRINT },  /* 舍入到零 */
        { 0x0C, "frinta", INST_TYPE_FRINT },  /* 舍入到最近（偶数） */
        { 0x0E, "frintx", INST_TYPE_FRINT },  /* 精确舍入 */
        { 0x0F, "frinti", INST_TYPE_FRINT },  /* 使用FPCR舍入 */
    };
    
    for (size_t i = 0; i < sizeof(fp_1src_ops) / sizeof(fp_1src_ops[0]); i++) {
        if (fp_1src_ops[i].opcode == opcode) {
            SAFE_STRCPY(result->mnemonic, fp_1src_ops[i].name);
            result->type = fp_1src_ops[i].type;
            
            /* 处理fcvt的目标类型 */
            if (opcode >= 0x04 && opcode <= 0x07) {
                uint8_t opc = opcode & 0x03;
                if (opc == 0) result->rd_type = REG_TYPE_S;
                else if (opc == 1) result->rd_type = REG_TYPE_D;
                else if (opc == 3) result->rd_type = REG_TYPE_H;
            }
            return true;
        }
    }
    
    return false;
}

/* ========== 浮点数据处理（2源）========== */

/**
 * 解析浮点数据处理（2源）- FMUL/FDIV/FADD/FSUB等
 * 编码：M|0|S|11110|ftype|1|Rm|opcode|10|Rn|Rd
 * mask: 0x5F200C00, value: 0x1E200800
 */
static bool decode_fp_data_proc_2src(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t M = BIT(inst, 31);
    uint8_t S = BIT(inst, 29);
    uint8_t ftype = BITS(inst, 22, 23);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t opcode = BITS(inst, 12, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (M != 0 || S != 0) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->rm = rm;
    result->has_imm = false;
    result->rd_type = get_fp_reg_type(ftype);
    result->rn_type = get_fp_reg_type(ftype);
    result->rm_type = get_fp_reg_type(ftype);
    
    static const struct {
        uint8_t opcode;
        const char *name;
        inst_type_t type;
    } fp_2src_ops[] = {
        { 0x00, "fmul",   INST_TYPE_FMUL },
        { 0x01, "fdiv",   INST_TYPE_FDIV },
        { 0x02, "fadd",   INST_TYPE_FADD },
        { 0x03, "fsub",   INST_TYPE_FSUB },
        { 0x04, "fmax",   INST_TYPE_FMAX },
        { 0x05, "fmin",   INST_TYPE_FMIN },
        { 0x06, "fmaxnm", INST_TYPE_FMAX },
        { 0x07, "fminnm", INST_TYPE_FMIN },
        { 0x08, "fnmul",  INST_TYPE_FMUL },
    };
    
    for (size_t i = 0; i < sizeof(fp_2src_ops) / sizeof(fp_2src_ops[0]); i++) {
        if (fp_2src_ops[i].opcode == opcode) {
            SAFE_STRCPY(result->mnemonic, fp_2src_ops[i].name);
            result->type = fp_2src_ops[i].type;
            return true;
        }
    }
    
    return false;
}

/* ========== 浮点数据处理（3源）========== */

/**
 * 解析浮点数据处理（3源）- FMADD/FMSUB/FNMADD/FNMSUB
 * 编码：M|0|S|11111|ftype|o1|Rm|o0|Ra|Rn|Rd
 * mask: 0x5F000000, value: 0x1F000000
 */
static bool decode_fp_data_proc_3src(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t M = BIT(inst, 31);
    uint8_t S = BIT(inst, 29);
    uint8_t ftype = BITS(inst, 22, 23);
    uint8_t o1 = BIT(inst, 21);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t o0 = BIT(inst, 15);
    uint8_t ra = BITS(inst, 10, 14);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (M != 0 || S != 0) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->rm = rm;
    result->ra = ra;
    result->has_imm = false;
    result->rd_type = get_fp_reg_type(ftype);
    result->rn_type = get_fp_reg_type(ftype);
    result->rm_type = get_fp_reg_type(ftype);
    
    uint8_t op = (o1 << 1) | o0;
    static const struct {
        const char *name;
        inst_type_t type;
    } fp_3src_ops[] = {
        { "fmadd",  INST_TYPE_FMADD  },
        { "fmsub",  INST_TYPE_FMSUB  },
        { "fnmadd", INST_TYPE_FNMADD },
        { "fnmsub", INST_TYPE_FNMSUB }
    };
    
    if (op < 4) {
        SAFE_STRCPY(result->mnemonic, fp_3src_ops[op].name);
        result->type = fp_3src_ops[op].type;
        return true;
    }
    
    return false;
}

/* ========== 浮点比较指令 ========== */

/**
 * 解析浮点比较 - FCMP/FCMPE
 * 编码：M|0|S|11110|ftype|1|Rm|op|1000|Rn|opcode2
 * mask: 0x5F203C00, value: 0x1E202000
 */
static bool decode_fp_compare(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t M = BIT(inst, 31);
    uint8_t S = BIT(inst, 29);
    uint8_t ftype = BITS(inst, 22, 23);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t op = BITS(inst, 14, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t opcode2 = BITS(inst, 0, 4);
    
    if (M != 0 || S != 0) return false;
    if (op != 0) return false;
    
    result->rn = rn;
    result->rm = rm;
    result->has_imm = false;
    result->rn_type = get_fp_reg_type(ftype);
    result->rm_type = get_fp_reg_type(ftype);
    result->type = INST_TYPE_FCMP;
    
    /* opcode2决定比较类型 */
    switch (opcode2) {
        case 0x00:  /* FCMP Fn, Fm */
            SAFE_STRCPY(result->mnemonic, "fcmp");
            result->type = INST_TYPE_FCMP;
            break;
        case 0x08:  /* FCMP Fn, #0.0 */
            SAFE_STRCPY(result->mnemonic, "fcmp");
            result->type = INST_TYPE_FCMP;
            result->has_imm = true;
            result->imm = 0;
            break;
        case 0x10:  /* FCMPE Fn, Fm */
            SAFE_STRCPY(result->mnemonic, "fcmpe");
            result->type = INST_TYPE_FCMPE;
            break;
        case 0x18:  /* FCMPE Fn, #0.0 */
            SAFE_STRCPY(result->mnemonic, "fcmpe");
            result->type = INST_TYPE_FCMPE;
            result->has_imm = true;
            result->imm = 0;
            break;
        default:
            return false;
    }
    
    return true;
}

/* ========== 浮点条件比较 ========== */

/**
 * 解析浮点条件比较 - FCCMP/FCCMPE
 * 编码：M|0|S|11110|ftype|1|Rm|cond|01|Rn|op|nzcv
 * mask: 0x5F200C00, value: 0x1E200400
 */
static bool decode_fp_cond_compare(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t M = BIT(inst, 31);
    uint8_t S = BIT(inst, 29);
    uint8_t ftype = BITS(inst, 22, 23);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t cond = BITS(inst, 12, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t op = BIT(inst, 4);
    uint8_t nzcv = BITS(inst, 0, 3);
    
    if (M != 0 || S != 0) return false;
    
    result->rn = rn;
    result->rm = rm;
    result->cond = cond;
    result->imm = nzcv;
    result->has_imm = true;
    result->rn_type = get_fp_reg_type(ftype);
    result->rm_type = get_fp_reg_type(ftype);
    result->type = INST_TYPE_FCCMP;
    
    SAFE_STRCPY(result->mnemonic, op ? "fccmpe" : "fccmp");
    
    return true;
}

/* ========== 浮点条件选择 ========== */

/**
 * 解析浮点条件选择 - FCSEL
 * 编码：M|0|S|11110|ftype|1|Rm|cond|11|Rn|Rd
 * mask: 0x5F200C00, value: 0x1E200C00
 */
static bool decode_fp_cond_select(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t M = BIT(inst, 31);
    uint8_t S = BIT(inst, 29);
    uint8_t ftype = BITS(inst, 22, 23);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t cond = BITS(inst, 12, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (M != 0 || S != 0) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->rm = rm;
    result->cond = cond;
    result->has_imm = false;
    result->rd_type = get_fp_reg_type(ftype);
    result->rn_type = get_fp_reg_type(ftype);
    result->rm_type = get_fp_reg_type(ftype);
    result->type = INST_TYPE_FCSEL;
    
    SAFE_STRCPY(result->mnemonic, "fcsel");
    
    return true;
}

/* ========== 浮点/整数转换 ========== */

/**
 * 解析浮点/整数转换 - FCVT, SCVTF, UCVTF, FMOV(GPR<->FP)
 * 编码: sf|0|S|11110|ftype|1|rmode|opcode|000000|Rn|Rd
 * mask: 0x5F20FC00, value: 0x1E200000
 */
static bool decode_fp_int_conv(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t sf = BIT(inst, 31);
    uint8_t S = BIT(inst, 29);
    uint8_t ftype = BITS(inst, 22, 23);
    uint8_t rmode = BITS(inst, 19, 20);
    uint8_t opcode = BITS(inst, 16, 18);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (S != 0) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->has_imm = false;
    
    reg_type_t fp_type = get_fp_reg_type(ftype);
    reg_type_t gpr_type = sf ? REG_TYPE_X : REG_TYPE_W;
    
    /* 根据rmode和opcode确定操作 */
    uint8_t op = (rmode << 3) | opcode;
    
    switch (op) {
        /* 浮点转整数（舍入到零） */
        case 0x18:  /* FCVTZS (scalar, integer) */
            SAFE_STRCPY(result->mnemonic, "fcvtzs");
            result->rd_type = gpr_type;
            result->rn_type = fp_type;
            result->type = INST_TYPE_FCVTZS;
            break;
        case 0x19:  /* FCVTZU (scalar, integer) */
            SAFE_STRCPY(result->mnemonic, "fcvtzu");
            result->rd_type = gpr_type;
            result->rn_type = fp_type;
            result->type = INST_TYPE_FCVTZU;
            break;
            
        /* 整数转浮点 */
        case 0x02:  /* SCVTF (scalar, integer) */
            SAFE_STRCPY(result->mnemonic, "scvtf");
            result->rd_type = fp_type;
            result->rn_type = gpr_type;
            result->type = INST_TYPE_SCVTF;
            break;
        case 0x03:  /* UCVTF (scalar, integer) */
            SAFE_STRCPY(result->mnemonic, "ucvtf");
            result->rd_type = fp_type;
            result->rn_type = gpr_type;
            result->type = INST_TYPE_UCVTF;
            break;
            
        /* FMOV (GPR <-> FP) */
        case 0x06:  /* FMOV Sd, Wn 或 FMOV Dd, Xn */
            SAFE_STRCPY(result->mnemonic, "fmov");
            result->rd_type = fp_type;
            result->rn_type = gpr_type;
            result->type = INST_TYPE_FMOV;
            break;
        case 0x07:  /* FMOV Wd, Sn 或 FMOV Xd, Dn */
            SAFE_STRCPY(result->mnemonic, "fmov");
            result->rd_type = gpr_type;
            result->rn_type = fp_type;
            result->type = INST_TYPE_FMOV;
            break;
            
        /* 其他舍入模式的转换 */
        case 0x00:  /* FCVTNS */
            SAFE_STRCPY(result->mnemonic, "fcvtns");
            result->rd_type = gpr_type;
            result->rn_type = fp_type;
            result->type = INST_TYPE_FCVTZS;
            break;
        case 0x01:  /* FCVTNU */
            SAFE_STRCPY(result->mnemonic, "fcvtnu");
            result->rd_type = gpr_type;
            result->rn_type = fp_type;
            result->type = INST_TYPE_FCVTZU;
            break;
        case 0x08:  /* FCVTPS */
            SAFE_STRCPY(result->mnemonic, "fcvtps");
            result->rd_type = gpr_type;
            result->rn_type = fp_type;
            result->type = INST_TYPE_FCVTZS;
            break;
        case 0x09:  /* FCVTPU */
            SAFE_STRCPY(result->mnemonic, "fcvtpu");
            result->rd_type = gpr_type;
            result->rn_type = fp_type;
            result->type = INST_TYPE_FCVTZU;
            break;
        case 0x10:  /* FCVTMS */
            SAFE_STRCPY(result->mnemonic, "fcvtms");
            result->rd_type = gpr_type;
            result->rn_type = fp_type;
            result->type = INST_TYPE_FCVTZS;
            break;
        case 0x11:  /* FCVTMU */
            SAFE_STRCPY(result->mnemonic, "fcvtmu");
            result->rd_type = gpr_type;
            result->rn_type = fp_type;
            result->type = INST_TYPE_FCVTZU;
            break;
        case 0x04:  /* FCVTAS */
            SAFE_STRCPY(result->mnemonic, "fcvtas");
            result->rd_type = gpr_type;
            result->rn_type = fp_type;
            result->type = INST_TYPE_FCVTZS;
            break;
        case 0x05:  /* FCVTAU */
            SAFE_STRCPY(result->mnemonic, "fcvtau");
            result->rd_type = gpr_type;
            result->rn_type = fp_type;
            result->type = INST_TYPE_FCVTZU;
            break;
            
        default:
            return false;
    }
    
    result->is_64bit = sf;
    return true;
}

/* ========== 浮点立即数 ========== */

/**
 * 解析浮点立即数移动 - FMOV (immediate)
 * 编码：M|0|S|11110|ftype|1|imm8|100|imm5|Rd
 * mask: 0x5F201C00, value: 0x1E201000
 */
static bool decode_fp_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t M = BIT(inst, 31);
    uint8_t S = BIT(inst, 29);
    uint8_t ftype = BITS(inst, 22, 23);
    uint8_t imm8 = BITS(inst, 13, 20);
    uint8_t imm5 = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (M != 0 || S != 0) return false;
    if (imm5 != 0) return false;  /* imm5必须为0 */
    
    result->rd = rd;
    result->imm = imm8;
    result->has_imm = true;
    result->rd_type = get_fp_reg_type(ftype);
    result->type = INST_TYPE_FMOV;
    
    SAFE_STRCPY(result->mnemonic, "fmov");
    
    return true;
}

/* ========== 浮点加载/存储 ========== */

/**
 * 解析浮点加载/存储（无符号偏移）
 * 这些指令已在 arm64_disasm_loadstore.c 中处理（V=1的情况）
 * 这里提供额外的SIMD加载/存储支持
 */

/* ========== 高级SIMD标量指令 ========== */

/**
 * 解析高级SIMD标量复制 - DUP (element)
 * 编码：01|0|11110000|imm5|0|imm4|1|Rn|Rd
 * mask: 0xFFE0FC00, value: 0x5E000400
 */
static bool decode_simd_scalar_dup(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t imm5 = BITS(inst, 16, 20);
    uint8_t imm4 = BITS(inst, 11, 14);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    if (imm4 != 0) return false;
    
    result->rd = rd;
    result->rn = rn;
    result->has_imm = false;
    
    /* 根据imm5确定元素大小 */
    if (imm5 & 0x01) {
        result->rd_type = REG_TYPE_B;
        result->imm = (imm5 >> 1) & 0x0F;
    } else if (imm5 & 0x02) {
        result->rd_type = REG_TYPE_H;
        result->imm = (imm5 >> 2) & 0x07;
    } else if (imm5 & 0x04) {
        result->rd_type = REG_TYPE_S;
        result->imm = (imm5 >> 3) & 0x03;
    } else if (imm5 & 0x08) {
        result->rd_type = REG_TYPE_D;
        result->imm = (imm5 >> 4) & 0x01;
    } else {
        return false;
    }
    
    result->rn_type = REG_TYPE_V;
    result->has_imm = true;
    result->type = INST_TYPE_MOV;
    
    SAFE_STRCPY(result->mnemonic, "dup");
    
    return true;
}

/* ========== 高级SIMD标量算术 ========== */

/**
 * 解析高级SIMD标量三寄存器（相同类型）
 * 编码：01|U|11110|size|1|Rm|opcode|1|Rn|Rd
 * mask: 0xDF200400, value: 0x5E200400
 */
static bool decode_simd_scalar_3same(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t U = BIT(inst, 29);
    uint8_t size = BITS(inst, 22, 23);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t opcode = BITS(inst, 11, 15);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    result->rd = rd;
    result->rn = rn;
    result->rm = rm;
    result->has_imm = false;
    
    /* 确定寄存器类型 */
    static const reg_type_t size_to_type[] = { REG_TYPE_B, REG_TYPE_H, REG_TYPE_S, REG_TYPE_D };
    result->rd_type = size_to_type[size];
    result->rn_type = size_to_type[size];
    result->rm_type = size_to_type[size];
    
    /* 根据U和opcode确定操作 */
    uint8_t op = (U << 5) | opcode;
    
    static const struct {
        uint8_t op;
        const char *name;
        bool fp_only;  /* 是否仅用于浮点 */
    } simd_scalar_ops[] = {
        { 0x10, "add",    false },
        { 0x30, "sub",    false },
        { 0x1B, "fmulx",  true  },
        { 0x1C, "fcmeq",  true  },
        { 0x1F, "frecps", true  },
        { 0x3C, "fcmge",  true  },
        { 0x3D, "facge",  true  },
        { 0x3F, "frsqrts",true  },
        { 0x1A, "fadd",   true  },
        { 0x3A, "fsub",   true  },
        { 0x1E, "fmax",   true  },
        { 0x3E, "fmin",   true  },
        { 0x1D, "fmul",   true  },
        { 0x3D, "fdiv",   true  },
    };
    
    for (size_t i = 0; i < sizeof(simd_scalar_ops) / sizeof(simd_scalar_ops[0]); i++) {
        if (simd_scalar_ops[i].op == op) {
            SAFE_STRCPY(result->mnemonic, simd_scalar_ops[i].name);
            result->type = INST_TYPE_ADD;
            return true;
        }
    }
    
    return false;
}

/* ========== 高级SIMD标量两寄存器杂项 ========== */

/**
 * 解析高级SIMD标量两寄存器杂项
 * 编码：01|U|11110|size|10000|opcode|10|Rn|Rd
 * mask: 0xDF3FFC00, value: 0x5E200800 (部分)
 */
static bool decode_simd_scalar_2reg_misc(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t U = BIT(inst, 29);
    uint8_t size = BITS(inst, 22, 23);
    uint8_t opcode = BITS(inst, 12, 16);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rd = BITS(inst, 0, 4);
    
    result->rd = rd;
    result->rn = rn;
    result->has_imm = false;
    
    static const reg_type_t size_to_type[] = { REG_TYPE_B, REG_TYPE_H, REG_TYPE_S, REG_TYPE_D };
    result->rd_type = size_to_type[size];
    result->rn_type = size_to_type[size];
    
    uint8_t op = (U << 5) | opcode;
    
    static const struct {
        uint8_t op;
        const char *name;
    } scalar_2reg_ops[] = {
        { 0x03, "suqadd"  },
        { 0x07, "sqabs"   },
        { 0x08, "cmgt"    },  /* vs 0 */
        { 0x09, "cmeq"    },  /* vs 0 */
        { 0x0A, "cmlt"    },  /* vs 0 */
        { 0x0B, "abs"     },
        { 0x0C, "fcmgt"   },  /* vs 0 */
        { 0x0D, "fcmeq"   },  /* vs 0 */
        { 0x0E, "fcmlt"   },  /* vs 0 */
        { 0x1A, "fcvtns"  },
        { 0x1B, "fcvtms"  },
        { 0x1C, "fcvtas"  },
        { 0x1D, "scvtf"   },
        { 0x23, "usqadd"  },
        { 0x27, "sqneg"   },
        { 0x28, "cmge"    },  /* vs 0 */
        { 0x29, "cmle"    },  /* vs 0 */
        { 0x2B, "neg"     },
        { 0x2C, "fcmge"   },  /* vs 0 */
        { 0x2D, "fcmle"   },  /* vs 0 */
        { 0x3A, "fcvtpu"  },
        { 0x3B, "fcvtzu"  },
        { 0x3D, "ucvtf"   },
    };
    
    for (size_t i = 0; i < sizeof(scalar_2reg_ops) / sizeof(scalar_2reg_ops[0]); i++) {
        if (scalar_2reg_ops[i].op == op) {
            SAFE_STRCPY(result->mnemonic, scalar_2reg_ops[i].name);
            result->type = INST_TYPE_MOV;
            return true;
        }
    }
    
    return false;
}

/* ========== 浮点/SIMD解码表 ========== */

const decode_entry_t fp_simd_decode_table[] = {
    /* 浮点比较: bits[28:24] = 11110, bits[21] = 1, bits[13:10] = 1000 */
    DECODE_ENTRY(0x5F203C00, 0x1E202000, decode_fp_compare),
    
    /* 浮点条件比较: bits[28:24] = 11110, bits[21] = 1, bits[11:10] = 01 */
    DECODE_ENTRY(0x5F200C00, 0x1E200400, decode_fp_cond_compare),
    
    /* 浮点条件选择: bits[28:24] = 11110, bits[21] = 1, bits[11:10] = 11 */
    DECODE_ENTRY(0x5F200C00, 0x1E200C00, decode_fp_cond_select),
    
    /* 浮点数据处理（2源）: bits[28:24] = 11110, bits[21] = 1, bits[11:10] = 10 */
    DECODE_ENTRY(0x5F200C00, 0x1E200800, decode_fp_data_proc_2src),
    
    /* 浮点数据处理（1源）: bits[28:24] = 11110, bits[21] = 1, bits[14:10] = 10000 */
    DECODE_ENTRY(0x5F207C00, 0x1E204000, decode_fp_data_proc_1src),
    
    /* 浮点立即数: bits[28:24] = 11110, bits[21] = 1, bits[12:10] = 100 */
    DECODE_ENTRY(0x5F201C00, 0x1E201000, decode_fp_imm),
    
    /* 浮点/整数转换: bits[28:24] = 11110, bits[21] = 1, bits[15:10] = 000000 */
    DECODE_ENTRY(0x5F20FC00, 0x1E200000, decode_fp_int_conv),
    
    /* 浮点数据处理（3源）: bits[28:24] = 11111 */
    DECODE_ENTRY(0x5F000000, 0x1F000000, decode_fp_data_proc_3src),
    
    /* SIMD标量复制 */
    DECODE_ENTRY(0xFFE0FC00, 0x5E000400, decode_simd_scalar_dup),
    
    /* SIMD标量三寄存器（相同类型） */
    DECODE_ENTRY(0xDF200400, 0x5E200400, decode_simd_scalar_3same),
    
    /* SIMD标量两寄存器杂项 */
    DECODE_ENTRY(0xDF3E0C00, 0x5E200800, decode_simd_scalar_2reg_misc),
};

const size_t fp_simd_decode_table_size = ARRAY_SIZE(fp_simd_decode_table);

/* ========== 主浮点/SIMD解析函数（表驱动） ========== */

/**
 * 解析浮点/SIMD指令
 */
bool decode_fp_simd(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    return decode_with_table(fp_simd_decode_table, fp_simd_decode_table_size,
                            inst, addr, result);
}
