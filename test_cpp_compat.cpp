/**
 * C++兼容性测试
 * 验证ARM64反汇编器头文件可以在C++中正确编译和链接
 */

#include "arm64_disasm.h"
#include "arm64_decode_table.h"
#include <cstdio>

int main() {
    // 测试基本反汇编调用: NOP (0xD503201F)
    disasm_inst_t inst;
    bool ok = disassemble_arm64(0xD503201F, 0x1000, &inst);

    if (!ok) {
        std::printf("FAIL: disassemble_arm64 returned false for NOP\n");
        return 1;
    }

    // 测试格式化输出
    char buf[128];
    format_instruction(&inst, buf, sizeof(buf));
    std::printf("C++ compat test: %s\n", buf);

    // 测试分析辅助函数
    bool is_branch = is_branch_instruction(&inst);
    bool is_ls = is_load_store_instruction(&inst);

    // NOP 不应该是分支或加载/存储指令
    if (is_branch || is_ls) {
        std::printf("FAIL: NOP misclassified\n");
        return 1;
    }

    // 测试解码表符号可访问
    std::printf("Top-level decode table size: %zu\n", top_level_decode_table_size);

    std::printf("PASS: C++ compatibility test succeeded\n");
    return 0;
}
