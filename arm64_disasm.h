#ifndef ARM64_DISASM_H
#define ARM64_DISASM_H

#include <stdint.h>
#include <stdbool.h>

/* 寄存器类型 */
typedef enum {
    REG_TYPE_X,      // 64位通用寄存器 X0-X30
    REG_TYPE_W,      // 32位通用寄存器 W0-W30
    REG_TYPE_SP,     // 栈指针
    REG_TYPE_XZR,    // 零寄存器 XZR
    REG_TYPE_WZR,    // 零寄存器 WZR
    REG_TYPE_V,      // SIMD/FP寄存器
    REG_TYPE_B,      // 8位 SIMD寄存器
    REG_TYPE_H,      // 16位 SIMD寄存器
    REG_TYPE_S,      // 32位 SIMD寄存器
    REG_TYPE_D,      // 64位 SIMD寄存器
    REG_TYPE_Q       // 128位 SIMD寄存器
} reg_type_t;

/* 指令类型 */
typedef enum {
    INST_TYPE_UNKNOWN,
    INST_TYPE_LDR,          // 加载寄存器
    INST_TYPE_LDRB,         // 加载字节
    INST_TYPE_LDRH,         // 加载半字
    INST_TYPE_LDRSW,        // 加载有符号字
    INST_TYPE_LDRSB,        // 加载有符号字节
    INST_TYPE_LDRSH,        // 加载有符号半字
    INST_TYPE_STR,          // 存储寄存器
    INST_TYPE_STRB,         // 存储字节
    INST_TYPE_STRH,         // 存储半字
    INST_TYPE_STP,          // 存储对
    INST_TYPE_LDP,          // 加载对
    INST_TYPE_MOV,          // 移动
    INST_TYPE_MOVZ,         // 移动立即数（零扩展）
    INST_TYPE_MOVN,         // 移动立即数（非）
    INST_TYPE_MOVK,         // 移动立即数（保持）
    INST_TYPE_ADD,          // 加法
    INST_TYPE_SUB,          // 减法
    INST_TYPE_ADDS,         // 加法（设置标志）
    INST_TYPE_SUBS,         // 减法（设置标志）
    INST_TYPE_ADR,          // 地址加载
    INST_TYPE_ADRP,         // 页地址加载
    INST_TYPE_B,            // 无条件分支
    INST_TYPE_BL,           // 带链接分支
    INST_TYPE_BR,           // 寄存器分支
    INST_TYPE_BLR,          // 寄存器带链接分支
    INST_TYPE_RET,          // 返回
    INST_TYPE_CBZ,          // 为零则分支
    INST_TYPE_CBNZ,         // 非零则分支
    INST_TYPE_TBZ,          // 测试位为零则分支
    INST_TYPE_TBNZ,         // 测试位非零则分支
    INST_TYPE_AND,          // 与
    INST_TYPE_ORR,          // 或
    INST_TYPE_EOR,          // 异或
    INST_TYPE_LSL,          // 逻辑左移
    INST_TYPE_LSR,          // 逻辑右移
    INST_TYPE_ASR,          // 算术右移
    INST_TYPE_CMP,          // 比较
    INST_TYPE_CMN,          // 比较负数
    INST_TYPE_MUL,          // 乘法
    INST_TYPE_MADD,         // 乘加
    INST_TYPE_MSUB,         // 乘减
    INST_TYPE_SDIV,         // 有符号除法
    INST_TYPE_UDIV,         // 无符号除法
    INST_TYPE_NOP,          // 空操作
    INST_TYPE_MRS           // 从系统寄存器读取（MRS）
} inst_type_t;

/* 寻址模式 */
typedef enum {
    ADDR_MODE_NONE,
    ADDR_MODE_IMM_UNSIGNED,     // [Xn, #imm]
    ADDR_MODE_IMM_SIGNED,       // [Xn, #imm]
    ADDR_MODE_PRE_INDEX,        // [Xn, #imm]!
    ADDR_MODE_POST_INDEX,       // [Xn], #imm
    ADDR_MODE_REG_OFFSET,       // [Xn, Xm]
    ADDR_MODE_REG_EXTEND,       // [Xn, Wm, extend]
    ADDR_MODE_LITERAL           // 字面量池加载
} addr_mode_t;

/* 扩展/移位类型 */
typedef enum {
    EXTEND_UXTB = 0,    // 无符号扩展字节
    EXTEND_UXTH = 1,    // 无符号扩展半字
    EXTEND_UXTW = 2,    // 无符号扩展字
    EXTEND_UXTX = 3,    // 无符号扩展双字
    EXTEND_SXTB = 4,    // 有符号扩展字节
    EXTEND_SXTH = 5,    // 有符号扩展半字
    EXTEND_SXTW = 6,    // 有符号扩展字
    EXTEND_SXTX = 7,    // 有符号扩展双字
    EXTEND_LSL = 8      // 逻辑左移
} extend_t;

/* 反汇编指令结构 */
typedef struct {
    uint32_t raw;               // 原始指令编码
    uint64_t address;           // 指令地址
    inst_type_t type;           // 指令类型
    char mnemonic[16];          // 助记符
    
    /* 寄存器 */
    uint8_t rd;                 // 目标寄存器
    uint8_t rn;                 // 第一操作数寄存器
    uint8_t rm;                 // 第二操作数寄存器
    uint8_t rt2;                // 第二目标寄存器（用于STP/LDP）
    reg_type_t rd_type;
    reg_type_t rn_type;
    reg_type_t rm_type;
    
    /* 立即数 */
    int64_t imm;                // 立即数值
    bool has_imm;               // 是否有立即数
    
    /* 寻址模式 */
    addr_mode_t addr_mode;
    
    /* 扩展/移位 */
    extend_t extend_type;
    uint8_t shift_amount;
    
    /* 其他标志 */
    bool is_64bit;              // 是否为64位操作
    bool set_flags;             // 是否设置标志位
    
} disasm_inst_t;

/* 位操作宏 */
#define BITS(val, start, end)   (((val) >> (start)) & ((1ULL << ((end) - (start) + 1)) - 1))
#define BIT(val, pos)           (((val) >> (pos)) & 1)
#define SIGN_EXTEND(val, bits)  (((int64_t)(val) << (64 - (bits))) >> (64 - (bits)))

/* 函数原型 */

/**
 * 反汇编单条ARM64指令
 * @param raw_inst 32位原始指令编码
 * @param address 指令的虚拟地址
 * @param inst 输出的反汇编指令结构
 * @return true成功，false失败
 */
bool disassemble_arm64(uint32_t raw_inst, uint64_t address, disasm_inst_t *inst);

/**
 * 将反汇编指令格式化为字符串
 * @param inst 反汇编指令结构
 * @param buffer 输出缓冲区
 * @param buffer_size 缓冲区大小
 */
void format_instruction(const disasm_inst_t *inst, char *buffer, size_t buffer_size);

/**
 * 获取寄存器名称
 * @param reg_num 寄存器编号
 * @param reg_type 寄存器类型
 * @param buffer 输出缓冲区
 */
void get_register_name(uint8_t reg_num, reg_type_t reg_type, char *buffer);

/**
 * 解析加载/存储指令
 */
bool decode_load_store(uint32_t inst, uint64_t addr, disasm_inst_t *result);

/**
 * 解析数据处理指令（立即数）
 */
bool decode_data_proc_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result);

/**
 * 解析数据处理指令（寄存器）
 */
bool decode_data_proc_reg(uint32_t inst, uint64_t addr, disasm_inst_t *result);

/**
 * 解析分支指令
 */
bool decode_branch(uint32_t inst, uint64_t addr, disasm_inst_t *result);

/**
 * 批量反汇编
 * @param code 指令数组
 * @param count 指令数量
 * @param start_addr 起始地址
 */
void disassemble_block(const uint32_t *code, size_t count, uint64_t start_addr);

/**
 * 获取分支指令的目标地址
 * @param inst 反汇编指令结构
 * @param target 输出的目标地址
 * @return true如果是分支指令，false否则
 */
bool get_branch_target(const disasm_inst_t *inst, uint64_t *target);

/**
 * 判断指令是否为分支指令
 * @param inst 反汇编指令结构
 * @return true如果是分支指令
 */
bool is_branch_instruction(const disasm_inst_t *inst);

/**
 * 判断指令是否为加载/存储指令
 * @param inst 反汇编指令结构
 * @return true如果是加载/存储指令
 */
bool is_load_store_instruction(const disasm_inst_t *inst);

/**
 * 获取指令使用的寄存器列表
 * @param inst 反汇编指令结构
 * @param regs 输出的寄存器数组
 * @param count 输出的寄存器数量
 * @param max_count 数组最大容量
 */
void get_used_registers(const disasm_inst_t *inst, uint8_t *regs, 
                       size_t *count, size_t max_count);

/**
 * 获取指令的立即数值
 * @param inst 反汇编指令结构
 * @param value 输出的立即数值
 * @return true如果有立即数
 */
bool get_immediate_value(const disasm_inst_t *inst, int64_t *value);

/**
 * 打印指令的详细信息
 * @param inst 反汇编指令结构
 */
void print_instruction_details(const disasm_inst_t *inst);

/**
 * 打印单条指令
 * @param inst 反汇编指令结构
 */
void print_instruction(const disasm_inst_t *inst);

#endif /* ARM64_DISASM_H */

