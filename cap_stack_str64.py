from unicorn import *
# from unicorn.x86_const import *
from unicorn.arm64_const import *
from capstone import *
# from capstone.x86_const import *
from capstone.arm64_const import *

BASE_ADDRESS = 0x1000000
STACK_OFFSET = 0x200000

def setup(code_bin):
    """init capstone, return instance"""
    try:
        # Initialize emulator in X86-32bit mode
        # mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        # map 2MB memory for this emulation
        mu.mem_map(BASE_ADDRESS, 8 * 1024 * 1024)

        # write data to memory
        mu.mem_write(BASE_ADDRESS, code_bin)

        # initialize register for stack 
        # mu.reg_write(UC_X86_REG_ESP, BASE_ADDRESS + STACK_OFFSET)
        # mu.reg_write(UC_X86_REG_EBP, BASE_ADDRESS + STACK_OFFSET)
        mu.reg_write(UC_ARM64_REG_SP, BASE_ADDRESS+STACK_OFFSET)
        mu.reg_write(UC_ARM64_REG_X29, BASE_ADDRESS+STACK_OFFSET)

        # mu.reg_write(UC_ARM_REG_R7, BASE_ADDRESS+STACK_OFFSET)
        # mu.reg_write(UC_ARM_REG_R6, BASE_ADDRESS+STACK_OFFSET+0x21)
        # mu.reg_write(uc_arm_reg_r11)

    except UcError as e:
        print("ERROR SETUP:%s" % e)
        return None
    return mu


#TODO: calculuate the string size 
def get_string(offset,size=0x200):
    """read string from stack, example: lea     ecx, [ebp+var_44], enter 0x44 """
    # read_str = str(emu.mem_read(BASE_ADDRESS + STACK_OFFSET - offset, size))
    # temp = read_str[:read_str.find("\x00\x00")]
    # read_str = temp.replace("\x00","")
    read_str = str(emu.mem_read(BASE_ADDRESS + STACK_OFFSET + offset, size))
    # print int(read_str,16)
    print read_str, 'call '+'len: '+ str(len(read_str))
    temp = read_str[:read_str.find("\x00\x00")]
    read_str = temp.replace("\x00","")
    print "len + ", len(read_str)

    # print "%s"%emu.reg_read(UC_ARM_REG_R6)
    # read_str = str(emu.mem_read(int(emu.reg_read(UC_ARM64_REG_X19)), 0x20))
    # print read_str
    # temp = read_str[:0x12]
    # print temp
    # temp = read_str[:read_str.find("\x00\x00")]
    # read_str = temp.replace("\x00","")
    # print "%s"%emu.reg_read(UC_ARM_REG_R0)
    # read_str = str(emu.mem_read(int(emu.reg_read(UC_ARM_REG_R0)), 0x20))
    # temp = read_str[:read_str.find("\x00\x00")]
    # read_str = temp.replace("\x00","")

    # print "%s"%emu.reg_read(UC_ARM_REG_R0)
    # read_str = str(emu.mem_read(int(emu.reg_read(UC_ARM_REG_R7)), 0x20))
    # temp = read_str[:read_str.find("\x00\x00")]
    # read_str = temp.replace("\x00","")
    return read_str


def get_code():
    """ read bytes from idb"""
    try:
        start = SelStart()
        end = SelEnd()
        length =  end - start
        string = "".join([byte for byte in GetManyBytes( SelStart(), length)])
        return (start, end, string)
    except:
        return (0,0,0)


start,end, data = get_code()
if start:
    emu = setup(data)

    if emu:
        try:
            emu.emu_start(BASE_ADDRESS, BASE_ADDRESS + len(data))
            # print "%s"%emu.reg_read(UC_ARM_REG_R0)
            # print "%s"%emu.mem_read(int(emu.reg_read(UC_ARM_REG_R0)), 9)
        except UcError as e:
            print("ERROR START: %s" % e)
        # offset = AskLong(0, "Please enter stack offset")
        # comment = get_string(offset)
        comment = get_string(0x30)
        print "0x%x,%s" % (PrevHead(end), comment)
        print comment
        MakeComm(PrevHead(end), comment)