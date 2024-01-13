import ida_bytes, ida_ua

def GenerateFunctionSignature(funcBase):
    # 初始化要用到的变量
    instruction = ida_ua.insn_t()
    offset = 0
    signature = ""

    # 最多分析 100 条指令
    for count in range(1, 101):
        ida_ua.decode_insn(instruction, funcBase + offset)
        offset += instruction.size
        patternTemp = [0 for i in range(0, instruction.size)]


        # 遍历当前指令的全部操作数，并将部分操作数的机器码置为 ??
        for op in instruction.ops:
            if op.type == o_void:
                continue
            #  模糊位 ?? 的匹配条件：
            # and op.type != ida_ua.o_phrase and op.type != ida_ua.o_displ
            elif (op.type != ida_ua.o_reg):
                for index in range(op.offb, instruction.size):
                    patternTemp[index] = "??"


        # 读入除模糊位之外的机器码
        for index in range(0, instruction.size):
            if patternTemp[index] == "??":
                pass
            else:
                byteStr = format(ida_bytes.get_byte(instruction.ea + index), '02X')
                patternTemp[index] = byteStr
            signature = signature + ' ' + patternTemp[index]


        # 每分析 3 条指令，判断一次当前的 signature 是否唯一
        if count%3 == 0:
            if len(SearchPattern(signature, 2)) == 1:
                print('unique signature')
                return signature
            else:
                # print('not unique signature')
                continue

    return None


## 测试
print("pattern = ", GenerateFunctionSignature(0x320E21F))