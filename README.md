# ARM64 反汇编器

一个功能完善的ARM64(AArch64)架构反汇编器，使用纯C语言实现。采用表驱动架构，支持解析常见的ARM64指令，包括加载/存储、数据处理、分支、条件选择、原子操作等指令。

## 特性

### 支持的指令类型

#### 1. 加载/存储指令 (Load/Store)
- **LDR/STR** - 加载/存储寄存器（8/16/32/64位）
  - 立即数偏移：`ldr x0, [x1, #8]`
  - 寄存器偏移：`ldr x0, [x1, x2]`
  - 预索引：`ldr x0, [x1, #16]!`
  - 后索引：`ldr x0, [x1], #8`
  - 字面量池：`ldr x0, =0x1000`
- **LDRB/STRB** - 字节加载/存储
- **LDRH/STRH** - 半字加载/存储
- **LDRSW** - 加载有符号字
- **LDRSB/LDRSH** - 加载有符号字节/半字
- **LDP/STP** - 加载/存储对
- **扩展寻址** - 支持UXTW、SXTW、SXTX等扩展模式

#### 2. 数据处理指令 (Data Processing)
- **MOV系列**
  - MOVZ - 移动零扩展立即数
  - MOVN - 移动取反立即数
  - MOVK - 移动保持立即数
- **算术指令**
  - ADD/SUB - 加法/减法（立即数和寄存器）
  - ADDS/SUBS - 设置标志位的加减法
  - CMP/CMN - 比较指令
  - MUL/MADD/MSUB - 乘法/乘加/乘减
  - SDIV/UDIV - 有符号/无符号除法
- **逻辑指令**
  - AND/ORR/EOR - 逻辑与/或/异或
  - BIC/ORN/EON - 位清除/或非/异或非
  - TST - 测试位
- **移位指令**
  - LSL/LSR/ASR/ROR - 逻辑左移/逻辑右移/算术右移/循环右移
- **地址计算**
  - ADR - PC相对地址
  - ADRP - 页地址（4KB对齐）

#### 3. 条件选择指令 (Conditional Select)
- **CSEL** - 条件选择
- **CSINC** - 条件选择递增
- **CSINV** - 条件选择取反
- **CSNEG** - 条件选择取负
- **CSET/CSETM** - 条件设置/条件设置掩码
- **CINC/CINV/CNEG** - 条件递增/取反/取负

#### 4. 位操作指令 (Bit Manipulation)
- **CLZ/CLS** - 前导零/符号位计数
- **RBIT** - 位反转
- **REV/REV16/REV32** - 字节反转
- **EXTR** - 位域提取

#### 5. 分支指令 (Branch)
- **B/BL** - 无条件分支/带链接分支
- **B.cond** - 条件分支（EQ、NE、CS、CC等16种条件）
- **BR/BLR** - 寄存器分支/带链接寄存器分支
- **RET** - 返回
- **CBZ/CBNZ** - 为零/非零则分支
- **TBZ/TBNZ** - 测试位为零/非零则分支

#### 6. 原子操作指令 (Atomic Operations)
- **独占加载/存储**
  - LDXR/STXR - 独占加载/存储
  - LDAXR/STLXR - 独占加载-获取/存储-释放
  - LDAR/STLR - 加载-获取/存储-释放
- **原子内存操作 (ARMv8.1)**
  - LDADD - 原子加
  - LDCLR - 原子清除位
  - LDEOR - 原子异或
  - LDSET - 原子设置位
  - LDSMAX/LDSMIN - 原子有符号最大/最小
  - LDUMAX/LDUMIN - 原子无符号最大/最小
  - SWP - 原子交换
  - CAS - 比较并交换

#### 7. 系统指令
- **NOP** - 空操作
- **YIELD/WFE/WFI/SEV/SEVL** - 多核同步指令
- **MRS** - 读取系统寄存器

### 架构特点

1. **表驱动解码** - 使用解码表替代大量switch-case，易于扩展
2. **分层解码** - 顶层分发 → 子类别表 → 具体解码函数
3. **模块化设计** - 按指令类型分文件组织
4. **跨平台** - 支持Windows/Linux/macOS

### 核心功能

1. **指令解码** - 将32位机器码解析为指令结构
2. **立即数提取** - 准确提取并符号扩展立即数偏移量
3. **寄存器识别** - 识别X/W寄存器及特殊寄存器（SP、LR、FP等）
4. **格式化输出** - 生成易读的汇编语法
5. **批量反汇编** - 支持反汇编代码块
6. **辅助功能**
   - 分支目标地址计算
   - 指令类型判断
   - 寄存器使用分析
   - 详细信息输出


## API 参考

### 核心函数

#### 反汇编指令

```c
bool disassemble_arm64(uint32_t raw_inst, uint64_t address, disasm_inst_t *inst);
```
- **功能**：反汇编单条ARM64指令
- **参数**：
  - `raw_inst`: 32位机器码
  - `address`: 指令的虚拟地址
  - `inst`: 输出的反汇编结果
- **返回**：成功返回true，失败返回false

#### 格式化输出

```c
void format_instruction(const disasm_inst_t *inst, char *buffer, size_t buffer_size);
```
- **功能**：将反汇编结果格式化为字符串
- **参数**：
  - `inst`: 反汇编指令结构
  - `buffer`: 输出缓冲区
  - `buffer_size`: 缓冲区大小

#### 批量反汇编

```c
void disassemble_block(const uint32_t *code, size_t count, uint64_t start_addr);
```
- **功能**：批量反汇编指令块
- **参数**：
  - `code`: 指令数组
  - `count`: 指令数量
  - `start_addr`: 起始地址

### 辅助函数

#### 获取分支目标

```c
bool get_branch_target(const disasm_inst_t *inst, uint64_t *target);
```
- **功能**：计算分支指令的目标地址
- **返回**：如果是分支指令返回true

#### 判断指令类型

```c
bool is_branch_instruction(const disasm_inst_t *inst);
bool is_load_store_instruction(const disasm_inst_t *inst);
```

#### 获取使用的寄存器

```c
void get_used_registers(const disasm_inst_t *inst, uint8_t *regs, 
                       size_t *count, size_t max_count);
```

#### 获取立即数值

```c
bool get_immediate_value(const disasm_inst_t *inst, int64_t *value);
```

## 数据结构

### disasm_inst_t

主要的反汇编结果结构：

```c
typedef struct {
    uint32_t raw;               // 原始机器码
    uint64_t address;           // 指令地址
    inst_type_t type;           // 指令类型
    char mnemonic[16];          // 助记符
    
    // 寄存器
    uint8_t rd, rn, rm, rt2;    // 寄存器编号
    reg_type_t rd_type;         // 寄存器类型
    
    // 立即数
    int64_t imm;                // 立即数值（已符号扩展）
    bool has_imm;               // 是否有立即数
    
    // 寻址模式
    addr_mode_t addr_mode;      // 寻址模式
    
    // 其他
    extend_t extend_type;       // 扩展/移位类型
    uint8_t shift_amount;       // 移位量
    bool is_64bit;              // 是否为64位操作
} disasm_inst_t;
```

## 使用示例

### 示例1：基本反汇编

```c
#include "arm64_disasm.h"
#include <stdio.h>

int main() {
    // LDR指令：ldr x0, [x1, #8]
    uint32_t inst = 0xF9400421;
    disasm_inst_t result;
    
    if (disassemble_arm64(inst, 0x1000, &result)) {
        printf("指令类型: LDR\n");
        printf("目标寄存器: X%d\n", result.rd);
        printf("基址寄存器: X%d\n", result.rn);
        printf("立即数偏移: %lld\n", result.imm);
    }
    
    return 0;
}
```

### 示例2：批量反汇编

```c
#include "arm64_disasm.h"

int main() {
    uint32_t code[] = {
        0xA9BF7BFD,  // stp x29, x30, [sp, #-16]!
        0x910003FD,  // mov x29, sp
        0xF9400421,  // ldr x1, [x1, #8]
        0x8B000020,  // add x0, x1, x0
        0xA8C17BFD,  // ldp x29, x30, [sp], #16
        0xD65F03C0,  // ret
    };
    
    disassemble_block(code, 6, 0x1000);
    return 0;
}
```

### 示例3：分析函数调用

```c
#include "arm64_disasm.h"
#include <stdio.h>

void analyze_function(const uint32_t *code, size_t count, uint64_t addr) {
    for (size_t i = 0; i < count; i++) {
        disasm_inst_t inst;
        uint64_t cur_addr = addr + i * 4;
        
        if (disassemble_arm64(code[i], cur_addr, &inst)) {
            // 检测函数调用
            if (inst.type == INST_TYPE_BL) {
                uint64_t target;
                if (get_branch_target(&inst, &target)) {
                    printf("函数调用: 0x%llx -> 0x%llx\n", 
                           cur_addr, target);
                }
            }
            
            // 检测返回指令
            if (inst.type == INST_TYPE_RET) {
                printf("函数返回: 0x%llx\n", cur_addr);
            }
        }
    }
}
```

## 技术细节

### 指令编码格式

ARM64指令都是32位定长编码，通过不同的位字段来区分指令类型：

```
31 30 29 28 27 26 25 24 23 22 21 20 ... 0
|  |  |  |  |  |  |  |  |  |  |  |  ... |
└──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴─────┘
   操作码字段        操作数字段
```

### 立即数处理

1. **符号扩展**：使用`SIGN_EXTEND`宏处理有符号立即数
2. **位移缩放**：某些指令的立即数需要左移（如LDR的立即数需要根据数据大小左移）
3. **页对齐**：ADRP指令的立即数需要左移12位（4KB页）

### 寻址模式

支持以下寻址模式：

- **立即数偏移**：`[Xn, #imm]`
- **预索引**：`[Xn, #imm]!` - 先更新基址再访问
- **后索引**：`[Xn], #imm` - 先访问再更新基址
- **寄存器偏移**：`[Xn, Xm]`
- **扩展寄存器**：`[Xn, Wm, UXTW #2]`

## 限制和注意事项

1. **SIMD/FP指令**：当前版本对SIMD和浮点指令的支持有限
2. **系统指令**：仅支持常见的系统指令（NOP、WFE等）
3. **特权指令**：不支持EL1/EL2/EL3特权级指令
4. **加密扩展**：不支持加密扩展指令

## 贡献

欢迎提交Issue和Pull Request！

## 许可证

MIT License

## 参考资料

- ARM Architecture Reference Manual ARMv8
- ARM Cortex-A Series Programmer's Guide
- ARM Assembly Language Programming




