/**
 * ARM64反汇编器测试程序
 * 测试各种常见ARM64指令的反汇编
 */

#include "arm64_disasm.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// 测试用的ARM64机器码指令
static const uint32_t test_instructions[] = {
    // === LDR/STR指令测试 ===
    0xF9400000,  // ldr x0, [x0]
    0xF9400421,  // ldr x1, [x1, #8]
    0xF81F0FE0,  // stur x0, [sp, #-16]
    0xF8408420,  // ldr x0, [x1], #8
    0xF8410C00,  // ldr x0, [x0, #16]!
    0xB9400000,  // ldr w0, [x0]
    0x39400000,  // ldrb w0, [x0]
    0x79400000,  // ldrh w0, [x0]
    0xB9800000,  // ldrsw x0, [x0]
    0xF9000000,  // str x0, [x0]
    0xB9000000,  // str w0, [x0]
    0x39000000,  // strb w0, [x0]
    0x79000000,  // strh w0, [x0]
    
    // LDR/STR 寄存器偏移
    0xF8606820,  // ldr x0, [x1, x0]
    0xF8607820,  // ldr x0, [x1, x0, lsl #3]
    0xB8607820,  // ldr w0, [x1, w0, uxtw #2]
    
    // LDP/STP指令
    0xA9400FE0,  // ldp x0, x3, [sp]
    0xA9407BFD,  // ldp x29, x30, [sp]
    0xA9BF7BFD,  // stp x29, x30, [sp, #-16]!
    0xA9007BFD,  // stp x29, x30, [sp]
    
    // LDR literal
    0x58000000,  // ldr x0, <label>
    0x18000000,  // ldr w0, <label>
    
    // === MOV指令测试 ===
    0xD2800000,  // movz x0, #0
    0xD2800020,  // movz x0, #1
    0xD2A00000,  // movz x0, #0, lsl #16
    0x92800000,  // movn x0, #0
    0xF2800000,  // movk x0, #0
    0xAA0003E0,  // mov x0, x0
    0x2A0003E0,  // mov w0, w0
    
    // === ADD/SUB指令测试 ===
    0x91000000,  // add x0, x0, #0
    0x91000420,  // add x0, x1, #1
    0x91400000,  // add x0, x0, #0, lsl #12
    0xD1000000,  // sub x0, x0, #0
    0x8B000020,  // add x0, x1, x0
    0xCB000020,  // sub x0, x1, x0
    0xAB000020,  // adds x0, x1, x0
    0xEB000020,  // subs x0, x1, x0
    0xEB00003F,  // cmp x1, x0
    0xAB00003F,  // cmn x1, x0
    
    // === ADR/ADRP指令 ===
    0x10000000,  // adr x0, <label>
    0x90000000,  // adrp x0, <label>
    
    // === 逻辑指令测试 ===
    0x8A000020,  // and x0, x1, x0
    0xAA000020,  // orr x0, x1, x0
    0xCA000020,  // eor x0, x1, x0
    0x92400000,  // and x0, x0, #1
    0xB2400000,  // orr x0, x0, #1
    
    // === 移位指令 ===
    0xD3400000,  // ubfm x0, x0, #0, #0 (lsl)
    0xD3400020,  // lsr x0, x1, #0
    0x9AC02020,  // lsl x0, x1, x0
    0x9AC02420,  // lsr x0, x1, x0
    0x9AC02820,  // asr x0, x1, x0
    
    // === 乘除法指令 ===
    0x9B007C20,  // mul x0, x1, x0
    0x9AC00820,  // udiv x0, x1, x0
    0x9AC00C20,  // sdiv x0, x1, x0
    
    // === 分支指令测试 ===
    0x14000000,  // b <label>
    0x14000001,  // b <label+4>
    0x94000000,  // bl <label>
    0x54000000,  // b.eq <label>
    0x54000001,  // b.ne <label>
    0xB4000000,  // cbz x0, <label>
    0xB5000000,  // cbnz x0, <label>
    0x34000000,  // cbz w0, <label>
    0x35000000,  // cbnz w0, <label>
    0x36000000,  // tbz w0, #0, <label>
    0x37000000,  // tbnz w0, #0, <label>
    0xD61F0000,  // br x0
    0xD63F0000,  // blr x0
    0xD65F03C0,  // ret
    0xD65F0000,  // ret x0
    
    // === MRS 系统寄存器 ===
    0xD5384100,  // mrs x0, sp_el0
    0xD53C4101,  // mrs x1, sp_el1
    0xD53E4102,  // mrs x2, sp_el2
    0xD53C4003,  // mrs x3, spsr_el2
    0xD53C4024,  // mrs x4, elr_el2
    0xD53BD045,  // mrs x5, tpidr_el0
    0xD538D086,  // mrs x6, tpidr_el1
    0xD53CD047,  // mrs x7, tpidr_el2
    0xD53ED048,  // mrs x8, tpidr_el3
    
    // === 系统指令 ===
    0xD503201F,  // nop
    0xD503203F,  // yield
    0xD503205F,  // wfe
    0xD503207F,  // wfi
    
    // === 未知指令 ===
    0x00000000,  // udf #0
    0xFFFFFFFF,  // 无效指令
};

/**
 * 测试单条指令反汇编
 */
static void test_single_instruction(uint32_t inst, uint64_t addr) {
    disasm_inst_t result;
    
    if (disassemble_arm64(inst, addr, &result)) {
        char buffer[256];
        format_instruction(&result, buffer, sizeof(buffer));
        printf("0x%016llx:  %08x  %s\n", 
               (unsigned long long)addr, inst, buffer);
        
        // 如果有立即数，显示立即数信息
        if (result.has_imm) {
            printf("                             -> 立即数偏移: %lld (0x%llx)\n", 
                   (long long)result.imm, (unsigned long long)result.imm);
        }
    } else {
        printf("0x%016llx:  %08x  <反汇编失败>\n", 
               (unsigned long long)addr, inst);
    }
}

/**
 * 测试加载/存储指令
 */
static void test_load_store_instructions(void) {
    printf("\n========== 测试LDR/STR指令 ==========\n\n");
    
    uint32_t test_cases[] = {
        0xF9400000,  // ldr x0, [x0]
        0xF9400421,  // ldr x1, [x1, #8]
        0xF9401000,  // ldr x0, [x0, #32]
        0xF8408420,  // ldr x0, [x1], #8
        0xF8410C00,  // ldr x0, [x0, #16]!
        0xF81F0FE0,  // stur x0, [sp, #-16]
        0xF9000000,  // str x0, [x0]
        0xF9000420,  // str x0, [x1, #8]
        0xB9400000,  // ldr w0, [x0]
        0x39400000,  // ldrb w0, [x0]
        0x79400000,  // ldrh w0, [x0]
        0xB9800000,  // ldrsw x0, [x0]
        0xA9407BFD,  // ldp x29, x30, [sp]
        0xA9BF7BFD,  // stp x29, x30, [sp, #-16]!
    };
    
    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        test_single_instruction(test_cases[i], 0x1000 + i * 4);
    }
}

/**
 * 测试MOV指令
 */
static void test_mov_instructions(void) {
    printf("\n========== 测试MOV指令 ==========\n\n");
    
    uint32_t test_cases[] = {
        0xD2800000,  // movz x0, #0
        0xD2800020,  // movz x0, #1
        0xD2800400,  // movz x0, #32
        0xD2A00000,  // movz x0, #0, lsl #16
        0x92800000,  // movn x0, #0
        0xF2800000,  // movk x0, #0
        0xAA0003E0,  // mov x0, x0
        0xAA0103E0,  // mov x0, x1
    };
    
    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        test_single_instruction(test_cases[i], 0x2000 + i * 4);
    }
}

/**
 * 测试算术指令
 */
static void test_arithmetic_instructions(void) {
    printf("\n========== 测试算术指令 ==========\n\n");
    
    uint32_t test_cases[] = {
        0x91000420,  // add x0, x1, #1
        0x91000840,  // add x0, x2, #2
        0x91400000,  // add x0, x0, #0, lsl #12
        0xD1000420,  // sub x0, x1, #1
        0x8B000020,  // add x0, x1, x0
        0xCB000020,  // sub x0, x1, x0
        0xEB00003F,  // cmp x1, x0
        0xF1000C3F,  // cmp x1, #3
    };
    
    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        test_single_instruction(test_cases[i], 0x3000 + i * 4);
    }
}

/**
 * 测试分支指令
 */
static void test_branch_instructions(void) {
    printf("\n========== 测试分支指令 ==========\n\n");
    
    uint32_t test_cases[] = {
        0x14000001,  // b +4
        0x14000010,  // b +64
        0x17FFFFFF,  // b -4
        0x94000001,  // bl +4
        0x54000040,  // b.eq +8
        0x54000001,  // b.ne +4
        0xB4000040,  // cbz x0, +8
        0xB5000040,  // cbnz x0, +8
        0x36000040,  // tbz w0, #0, +8
        0xD61F0000,  // br x0
        0xD63F0000,  // blr x0
        0xD65F03C0,  // ret
    };
    
    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        test_single_instruction(test_cases[i], 0x4000 + i * 4);
    }
}

/**
 * 测试MRS系统寄存器读取
 */
static void test_mrs_instructions(void) {
    printf("\n========== 测试MRS指令 ==========\n\n");
    
    uint32_t test_cases[] = {
        0xD5384100,  // mrs x0, sp_el0
        0xD53C4101,  // mrs x1, sp_el1
        0xD53E4102,  // mrs x2, sp_el2
        0xD53BD045,  // mrs x5, tpidr_el0
        0xD53C4003,  // mrs x3, spsr_el2
        0xD53C4024,  // mrs x4, elr_el2
    };
    
    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        test_single_instruction(test_cases[i], 0x5000 + i * 4);
    }
}

/**
 * 测试详细信息输出
 */
static void test_detailed_output(void) {
    printf("\n========== 测试详细信息输出 ==========\n\n");
    
    disasm_inst_t inst;
    
    // 测试LDR指令
    if (disassemble_arm64(0xF9400421, 0x1000, &inst)) {
        print_instruction_details(&inst);
    }
    
    printf("\n");
    
    // 测试分支指令
    if (disassemble_arm64(0x14000010, 0x2000, &inst)) {
        print_instruction_details(&inst);
    }
}

/**
 * 主测试函数
 */
int main(int argc, char *argv[]) {
    // 设置Windows控制台为UTF-8编码
#ifdef _WIN32
    system("chcp 65001 >nul");
#endif
    
    printf("==============================================\n");
    printf("       ARM64反汇编器测试程序\n");
    printf("==============================================\n");
    
    // 测试所有指令
    printf("\n========== 完整指令集测试 ==========\n\n");
    uint64_t base_addr = 0x100000;
    size_t count = sizeof(test_instructions) / sizeof(test_instructions[0]);
    
    for (size_t i = 0; i < count; i++) {
        test_single_instruction(test_instructions[i], base_addr + i * 4);
    }
    
    // 分类测试
    test_load_store_instructions();
    test_mov_instructions();
    test_arithmetic_instructions();
    test_branch_instructions();
    test_mrs_instructions();
    test_detailed_output();
    
    // 批量反汇编测试
    printf("\n========== 批量反汇编测试 ==========\n\n");
    disassemble_block(test_instructions, count, base_addr);
    
    // 测试辅助函数
    printf("\n========== 测试辅助函数 ==========\n\n");
    
    disasm_inst_t inst;
    
    // 测试分支目标计算
    if (disassemble_arm64(0x14000010, 0x1000, &inst)) {
        uint64_t target;
        if (get_branch_target(&inst, &target)) {
            printf("分支指令目标地址: 0x%llx\n", (unsigned long long)target);
        }
        printf("是否为分支指令: %s\n", is_branch_instruction(&inst) ? "是" : "否");
    }
    
    // 测试寄存器提取
    if (disassemble_arm64(0x8B000020, 0x1000, &inst)) {
        uint8_t regs[8];
        size_t reg_count;
        get_used_registers(&inst, regs, &reg_count, 8);
        printf("使用的寄存器: ");
        for (size_t i = 0; i < reg_count; i++) {
            printf("x%d ", regs[i]);
        }
        printf("\n");
    }
    
    printf("\n==============================================\n");
    printf("              测试完成！\n");
    printf("==============================================\n");
    
    return 0;
}

