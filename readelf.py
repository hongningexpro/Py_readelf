#_*_coding:utf8_*_
import sys

##控制参数##############################################
g_show_help           = False     # 展示帮助信息       #
g_show_elf_head       = False     # 展示ELF文件头信息  #
g_show_section_table  = False     # 展示段表信息       #
##END###################################################

##ELF文件头信息#########################################
g_magic             = ""    # ELF魔数                  #
g_class             = 0     # 32or64位文件             #              
g_endian            = 0     # 字节序                   #
g_version           = 0     # 版本                     #
g_eType             = 0     # ELF文件类型              #
g_eMachine          = 0     # 机器类型                 #
g_eVersion          = 0     # ELF版本号                #
g_eEntry            = 0     # 入口地址                 #
g_ePhOff            = 0     # 程序头在文件中的偏移     #
g_eShOff            = 0     # 段表在文件中的偏移       #
g_eWord             = 0     # ELF标志位                #
g_eHSize            = 0     # ELF文件头本身大小        #
g_ePhentSize        = 0     # 程序头大小               #
g_ePhNum            = 0     # 程序头数量               #
g_eShentSize        = 0     # 段表描述符大小           #
g_eShNum            = 0     # 段表描述符数量           #
g_eShStrNdx         = 0     # 字符串表所在下标         #
##END###################################################

##ELF文件头描述信息字典#########################################
g_class_dict    = {1:"ELF32", 2:"ELF64"}    # 32还是64位文件   #
g_endian_dict   = {                         # 文件字节序       #
    0: "invalid format",                                       #
    1: "little endian",                                        #
    2: "big endian"                                            #
}                                                              #
g_eType_dict    = {                         # 文件类型         #
    1: "REL (Relocatable file)",                               #
    2: "EXEC (Executable file)",                               #
    3: "DYN (Shared object file)"                              #
}                                                              #
g_eMachine_dict = {                         # 机器类型         #
    1: "AT&T WE 32100",                                        #
    2: "SPARC",                                                #
    3: "Intel x86",                                            #
    4: "Motorola 68000",                                       #
    5: "Motorola 88000",                                       #
    6: "Intel 80860",                                          #
    62:"Advanced Micro Devices X86-64"                         #
}                                                              #
##END###########################################################

##段表相关信息#########################################
g_section_table_list = []   # 段表数据列表            #
g_sht_strtab = ""           # 字符串表数据            #
##END##################################################

##段头部描述信息字典###################################
g_sh_type_dict = {                                    #
    0           : "NULL",                             #
    1           : "PROGBITS",                         #
    2           : "SYMTAB",                           #
    3           : "STRTAB",                           #
    4           : "RELA",                             #
    5           : "HASH",                             #
    6           : "DYNAMIC",                          #
    7           : "NOTE",                             #
    8           : "NOBITS",                           #
    9           : "REL",                              #
    10          : "SHLIB",                            #
    11          : "DNYSYM",                           #
    14          : "INIT_ARRAY",                       #
    15          : "FINI_ARRAY",                       #
    16          : "PREINIT_ARRAY",                    #
    17          : "GROUP",                            #
    18          : "SYMTAB_SHNDX",                     #
    19          : "NUM",                              #
    0x60000000  : "LOOS",                             #
    0x6ffffff5  : "GNU_ATTRIBUTES",                   #
    0x6ffffff6  : "GNU_HASH",                         #
    0x6ffffff7  : "GNU_LIBLIST",                      #
    0x6ffffff8  : "CHECKSUM",                         #
    0x6ffffffa  : "LOSUNW",                           #
    0x6ffffffa  : "SUNW_move",                        #
    0x6ffffffb  : "SUNW_COMDAT",                      #
    0x6ffffffc  : "SUNW_syminfo",                     #
    0x6ffffffd  : "GNU_verdef",                       #
    0x6ffffffe  : "GNU_verneed",                      #
    0x6fffffff  : "GNU_versym",                       #
}                                                     #
##END##################################################

g_addr_size       = 0     # 根据文件类型确定地址大小
g_byte_2_int      = None  # 根据大小端确定转换方法



def usage():
    print("Usage: python readelf_EX <option(s)> elf-file")
    print(" Display information about the contents of ELF format file")
    print(" Options are:")
    print("-H       Display this information")
    print("-?       Display this information")
    print("-h       Display the ELF file header")
    print("-S       Display the sections' header")
    sys.exit(0)

def getoptions(argc, argv):
    global g_show_help
    global g_show_elf_head
    global g_show_section_table
    for i in range(1, argc-1):     # 这里去掉最后一个参数，最后一个参数为文件名
        p = argv[i]
        if not p.startswith("-"):
            print("invalid option:  \"%s\""%p)
            sys.exit(-1)
        p = p[1:]   # 去掉“-”选项标识符
        for x in p:
            if  p == "?" or p == "H":
                g_show_help = True
            elif p == "h":
                g_show_elf_head = True
            elif p == "S":
                g_show_section_table = True
            else:
                print("invalid option:  \"-%s\""%p)
                sys.exit(-1)

# 小端字节序byte转化为int
def little_endian_byte_2_int(src):
    i = 0 
    result = 0 
    for x in src:
        result += ord(x) * (16**i)
        i +=2 
    return result

# 大端字节序byte转化为int
def big_endian_byte_2_int(src):
    i = 0
    result = 0
    src = src[::-1]     # 逆序排列
    for x in src:
        result += ord(x) * (16**i)
        i +=2
    return result

# 解析elf文件头信息
def parse_elf_head(data):
    global g_magic
    global g_class
    global g_endian
    global g_version
    global g_eType
    global g_eMachine
    global g_eVersion
    global g_eEntry
    global g_ePhOff
    global g_eShOff
    global g_eWord
    global g_eHSize
    global g_ePhentSize
    global g_ePhNum
    global g_eShentSize
    global g_eShNum
    global g_eShStrNdx
    global g_addr_size
    global g_byte_2_int

    g_magic         = data[:16]                                 # 头部前16字节为elf魔数
    # 解析魔数字段
    g_class         = ord(g_magic[4])
    g_endian        = ord(g_magic[5])
    g_version       = ord(g_magic[6])
    # end
    if g_class == 1:
        # 32位
        g_addr_size = 4
    elif g_class == 2:
        # 64位
        g_addr_size = 8
    if g_endian == 1:
        # 小端字节序
        g_byte_2_int = little_endian_byte_2_int
    elif g_endian == 2:
        g_byte_2_int = big_endian_byte_2_int

    idx = 16
    g_eType         = g_byte_2_int(data[idx:idx+2])
    idx +=2
    g_eMachine      = g_byte_2_int(data[idx:idx+2])
    print(g_eMachine)
    idx +=2
    g_eVersion      = g_byte_2_int(data[idx:idx+4])
    idx +=4
    g_eEntry        = g_byte_2_int(data[idx:idx+g_addr_size])
    idx +=g_addr_size
    g_ePhOff        = g_byte_2_int(data[idx:idx+g_addr_size])
    idx +=g_addr_size
    g_eShOff        = g_byte_2_int(data[idx:idx+g_addr_size])
    idx +=g_addr_size
    g_eWord         = g_byte_2_int(data[idx:idx+4])
    idx +=4
    g_eHSize        = g_byte_2_int(data[idx:idx+2])
    idx +=2
    g_ePhentSize    = g_byte_2_int(data[idx:idx+2])
    idx +=2
    g_ePhNum        = g_byte_2_int(data[idx:idx+2])
    idx +=2
    g_eShentSize    = g_byte_2_int(data[idx:idx+2])
    idx +=2
    g_eShNum        = g_byte_2_int(data[idx:idx+2])
    idx +=2
    g_eShStrNdx     = g_byte_2_int(data[idx:idx+2])

"""
功能: 解析段表
参数: data: ELF文件数据
"""
def parse_section_table_list(data):
    global g_section_table_list
    idx = g_eShOff
    for i in range(g_eShNum):
        g_section_table_list.append(data[idx:idx+g_eShentSize]) 
        idx += g_eShentSize

# 解析字符串表
def parse_sht_strtab(data):
    global g_sht_strtab 
    if g_class == 1:
        index = 16
    elif g_class == 2:
        index = 24
    section = g_section_table_list[g_eShStrNdx]
    # type为3是字符串表
    sh_offset = g_byte_2_int(section[index:index+g_addr_size])
    index +=g_addr_size
    sh_size = g_byte_2_int(section[index:index+g_addr_size])
    g_sht_strtab = data[sh_offset:sh_offset+sh_size]

# 获取段名称
def get_sh_name_dsp(offset):
    text = ""
    for c in g_sht_strtab[offset:]:
        x = ord(c)
        if 0x20 <= x < 0x7F:
            text +=c
        elif x == 0:
            # 字符串表中每个段名以0结尾
            break
        else:
            # 不可见字符显示为"."
            text +="."
    return text

# 获取段标识描述信息
def get_sh_flags_dsp(sh_flags):
    result = ""
    mask = 1
    if sh_flags&(mask):
        result += "W"
    if sh_flags&(mask<<1):
        result += "A"
    if sh_flags&(mask<<2):
        result += "X"
    if sh_flags&(mask<<4):
        result +="M"
    if sh_flags&(mask<<5):
        result +="S"
    if sh_flags&(mask<<6):
        result +="I"
    if sh_flags&(mask<<7):
        result +="L"
    if sh_flags&(mask<<9):
        result +="G"
    if sh_flags&(mask<<10):
        result +="T"
    if sh_flags&(mask<<31):
        result +="E"
    return result


def show_elf_head():
    print("ELF Header:")
    print " Magic:  ",
    for i in g_magic:
        print "%02x"%ord(i),
    print("")   # 换行

    print(" Class:                              %s"%(g_class_dict.get(g_class)))
    print(" Data:                               %s"%(g_endian_dict.get(g_endian)))
    print(" Version:                            %s"%g_version)

    print(" Type:                               %s"%(g_eType_dict.get(g_eType)))
    print(" Machine:                            %s"%(g_eMachine_dict.get(g_eMachine)))
    print(" Version:                            0x%x"%g_eVersion)
    print(" Entry point address:                0x%x"%g_eEntry)
    print(" Start of program headers:           %d (bytes into file)"%g_ePhOff)
    print(" Start of section headers:           %d (bytes into file)"%g_eShOff)
    print(" Flags:                              0x%x"%g_eWord)
    print(" Size of this header:                %d (bytes)"%g_eHSize)
    print(" Size of program headers:            %d (bytes)"%g_ePhentSize)
    print(" Number of program headers:          %d"%g_ePhNum)
    print(" Size of section headers:            %d (bytes)"%g_eShentSize)
    print(" Number of section headers:          %d"%g_eShNum)
    print(" Section header string table index:  %d"%g_eShStrNdx)

def show_section_table():
    print("There are %d section headers, starting at offset 0x%x:"%(g_eShNum, g_eShOff))
    print("")
    print("Section Headers:")
    if g_class == 1:
        print("  [Nr] Name             Type            Addr     Off    Size   ES Flg Lk Inf Al")
    elif g_class == 2:
        print("  [Nr] Name              Type             Address           Offset")
        print("       Size              EntSize          Flags  Link  Info  Align")
    for section in g_section_table_list:
        index           = 0     # 偏移量
        idx             = g_section_table_list.index(section)
        sh_name         = g_byte_2_int(section[index:index+4])
        index +=4
        sh_type         = g_byte_2_int(section[index:index+4])
        index +=4
        sh_flags        = g_byte_2_int(section[index:index+g_addr_size])
        index +=g_addr_size
        sh_addr         = g_byte_2_int(section[index:index+g_addr_size])
        index +=g_addr_size
        sh_offset       = g_byte_2_int(section[index:index+g_addr_size])
        index +=g_addr_size
        sh_size         = g_byte_2_int(section[index:index+g_addr_size])
        index +=g_addr_size
        sh_link         = g_byte_2_int(section[index:index+4])
        index +=4
        sh_info         = g_byte_2_int(section[index:index+4])
        index +=4
        sh_addralign    = g_byte_2_int(section[index:index+g_addr_size])
        index +=g_addr_size
        sh_entsize      = g_byte_2_int(section[index:index+g_addr_size])
        if g_class == 1:
            print("  [%2d]%s%s%08x %06x %06x %02x %3s %2d %2d %2d"%(
                    idx,get_sh_name_dsp(sh_name).ljust(18),g_sh_type_dict.get(sh_type).ljust(16),sh_addr,sh_offset,sh_size,\
                            sh_entsize,get_sh_flags_dsp(sh_flags),sh_link,sh_info,sh_addralign))
        elif g_class == 2:
            print("  [%2d]%s%s% 016x   %08x"%(idx,get_sh_name_dsp(sh_name).ljust(19),g_sh_type_dict.get(sh_type).ljust(16),\
                                                                                            sh_addr,sh_offset))
            print("       %016x  %016x %s  %4d  %4d  %4d"%(sh_size, sh_entsize, get_sh_flags_dsp(sh_flags).center(5),\
                                                                                    sh_link,sh_info,sh_addralign))

    print("Key to Flags:")
    print("  W (write), A (alloc), X (execute), M (merge), S (strings)")
    print("  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)")
    print("  O (extra OS processing required) o (OS specific), p (processor specific)")


def main():
    argc = len(sys.argv) 
    if argc < 3:
        usage()

    elf_filename = sys.argv[argc-1]
    getoptions(argc, sys.argv)

    with open(elf_filename, "rb") as f:
        data = f.read()

    if g_show_help:
        usage()
    if g_show_elf_head:
        parse_elf_head(data)
        show_elf_head()
    if g_show_section_table:
        if not g_show_elf_head:
            # 如果没有解析头部信息,需要先解析头部信息，获取段表偏移和数量
            parse_elf_head(data)
        parse_section_table_list(data)
        parse_sht_strtab(data)
        show_section_table()

if __name__ == "__main__":
    main()
