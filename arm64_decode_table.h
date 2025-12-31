/**
 * ARM64反汇编器 - 表驱动解码架构
 * 定义解码表结构和相关宏
 */

#ifndef ARM64_DECODE_TABLE_H
#define ARM64_DECODE_TABLE_H

#include "arm64_disasm.h"

/* 解码器函数类型 */
typedef bool (*decode_func_t)(uint32_t inst, uint64_t addr, disasm_inst_t *result);

/* 解码表条目 */
typedef struct {
    uint32_t mask;          /* 掩码：用于提取关键位 */
    uint32_t value;         /* 期望值：与掩码后的结果比较 */
    decode_func_t decoder;  /* 解码函数 */
    const char *name;       /* 调试用：指令类别名称 */
} decode_entry_t;

/* 解码表组（用于分层解码） */
typedef struct {
    const decode_entry_t *entries;
    size_t count;
    const char *group_name;
} decode_group_t;

/* 便捷宏：定义解码表条目 */
#define DECODE_ENTRY(m, v, fn) { (m), (v), (fn), #fn }
#define DECODE_ENTRY_NAMED(m, v, fn, n) { (m), (v), (fn), (n) }

/* 便捷宏：计算数组大小 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* 安全字符串复制宏 */
#ifdef _WIN32
    #define SAFE_STRCPY(dst, src) strcpy_s((dst), sizeof(dst), (src))
#else
    #define SAFE_STRCPY(dst, src) do { \
        strncpy((dst), (src), sizeof(dst) - 1); \
        (dst)[sizeof(dst) - 1] = '\0'; \
    } while(0)
#endif

/*
 * ARM64 指令编码位字段说明：
 * 
 * 顶层分类基于 bits[28:25] (op0) 和 bits[31:29] (op1)
 * 
 * 主要指令类别：
 * - bits[28:26] = 100: 数据处理（立即数）
 * - bits[28:26] = 101: 分支、异常、系统
 * - bits[28:26] = x1x: 加载/存储
 * - bits[28:26] = x101: 数据处理（寄存器）
 */

/* ========== 分支指令解码表声明 ========== */
extern const decode_entry_t branch_decode_table[];
extern const size_t branch_decode_table_size;

/* ========== 数据处理（立即数）解码表声明 ========== */
extern const decode_entry_t data_proc_imm_decode_table[];
extern const size_t data_proc_imm_decode_table_size;

/* ========== 数据处理（寄存器）解码表声明 ========== */
extern const decode_entry_t data_proc_reg_decode_table[];
extern const size_t data_proc_reg_decode_table_size;

/* ========== 加载/存储解码表声明 ========== */
extern const decode_entry_t load_store_decode_table[];
extern const size_t load_store_decode_table_size;

/* ========== 浮点/SIMD解码表声明 ========== */
extern const decode_entry_t fp_simd_decode_table[];
extern const size_t fp_simd_decode_table_size;

/* ========== 顶层解码表声明 ========== */
extern const decode_entry_t top_level_decode_table[];
extern const size_t top_level_decode_table_size;

/* ========== 解码辅助函数 ========== */

/**
 * 在解码表中查找匹配的条目并执行解码
 * @param table 解码表
 * @param table_size 表大小
 * @param inst 原始指令
 * @param addr 指令地址
 * @param result 输出结果
 * @return 解码成功返回true
 */
bool decode_with_table(const decode_entry_t *table, size_t table_size,
                       uint32_t inst, uint64_t addr, disasm_inst_t *result);

#endif /* ARM64_DECODE_TABLE_H */
