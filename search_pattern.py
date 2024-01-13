import ida_bytes
import ida_ida

def SearchPattern(hexStr, num = 0):
    '''
    hexStr： 输入的特征码字符串，例：41 80 BE ?? ?? ?? ?? 0F 84 ?? ??
    num：    搜索到多少个结果时返回，为 0 时搜索全部匹配的地址
    '''

    # 生成掩码
    bMask = hexStr.replace('00', '01')
    bMask = bMask.replace('??', '00')
    bMask = bytes.fromhex(bMask)
    # print(bMask)

    # 生成模式码
    bPattern = hexStr.replace('??', '00')
    bPattern = bytes.fromhex(bPattern)
    # print(bPattern)


    results = []
    ea = ida_ida.inf_get_min_ea()

    while True:
        ea = ida_bytes.bin_search(
            ea + 1,
            ida_ida.inf_get_max_ea(),
            bPattern,
            bMask,
            1,
            ida_bytes.BIN_SEARCH_FORWARD| ida_bytes.BIN_SEARCH_NOBREAK| ida_bytes.BIN_SEARCH_NOSHOW)
        if ea == ida_idaapi.BADADDR:
            break
        else:
            # 这里可以稍作修改，让返回值变为当前函数的首地址
            results.append(hex(ea))
            if num != 0 and len(results) >= num:
                break
    # print("find {} result".format(len(results)))

    return results


## 测试
print(SearchPattern("48 8B C4 48 89 50 ??", 3))