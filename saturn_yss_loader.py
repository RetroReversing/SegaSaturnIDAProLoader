import os
from idc import *
from idaapi import *
from struct import unpack as up
from ctypes import *

FILE_FORMAT_NAME  = "Saturn YSS Save State"
FILE_SIGNATURE = "YSS"
FILE_SIGNATURE_OFFSET = 0
FILE_SIGNATURE_LENGTH = 3

# NOTE: struct unpack '<' is little endian, 'I' is unsigned int

# -----------------------------------------------------------------------
def dwordAt(li, off):
    # li.seek(off)
    s = li.read(4)
    if len(s) < 4:
        return 0
    return struct.unpack('<I', s)[0]

# -----------------------------------------------------------------------
def byteAt(li, off):
    # li.seek(off)
    s = li.read(1)
    if len(s) < 1:
        return 0
    return struct.unpack('<B', s)[0]

# -----------------------------------------------------------------------

def accept_file(li, filename):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param filename: name of the file, if it is an archive member name then the actual file doesn't exist
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    """

    # check the CECE signature
    li.seek(FILE_SIGNATURE_OFFSET)
    if li.read(FILE_SIGNATURE_LENGTH) == FILE_SIGNATURE:
        # accept the file
        return FILE_FORMAT_NAME

    # unrecognized format
    return 0

# -----------------------------------------------------------------------

def load_sh2_data(li):
    if not load_header(li):
        return 0

    if not StateCheckRetrieveHeader(li, "CART"):
        error("Invalid CART chunk")
        return

    if not StateCheckRetrieveHeader(li, "CS2 "):
        error("Invalid CS2 chunk")
        return

    msh2Size = StateCheckRetrieveHeader(li, "MSH2", False)
    if not msh2Size:
        error("Invalid MSH2 chunk")
        return
    programCounter = SH2LoadState(li, False, msh2Size)

    if not StateCheckRetrieveHeader(li, "SSH2"):
        error("Invalid SSH2 chunk")
        return

    if not StateCheckRetrieveHeader(li, "SCSP"):
        error("Invalid SCSP chunk")
        return

    if not StateCheckRetrieveHeader(li, "SCU "):
        error("Invalid SCU chunk")
        return
    
    if not StateCheckRetrieveHeader(li, "SMPC"):
        error("Invalid SMPC chunk")
        return
        
    vdp1Size = StateCheckRetrieveHeader(li, "VDP1", False)
    if not vdp1Size:
        error("Invalid VDP1 chunk")
        return
    Vdp1LoadState(li, vdp1Size)

    vdp2Size = StateCheckRetrieveHeader(li, "VDP2", False)
    if not vdp2Size:
        error("Invalid VDP2 chunk")
        return
    Vdp2LoadState(li, vdp2Size)

    if not StateCheckRetrieveHeader(li, "OTHR", False):
        error("Invalid OTHR chunk")
        return
    li.seek(li.tell()+0x10000) # Backup RAM (BUP)
    create_load_seg(li, 0x06000000, 0x06100000, 2, "HWRAM", "CODE")
    create_load_seg(li, 0x00200000, 0x00300000, 2, "LWRAM", "DATA")

    identify_vector_table()
    find_bios_funcs()
    find_parse_ip(li, 0x06000C00, False)
    find_parse_ip(li, 0x06002000, True)
    idaapi.jumpto(programCounter)
    return 1

# -----------------------------------------------------------------------
def create_load_seg(li, start, end, modificationType,name, segmentType="CODE"):
    # add_segm(0, start, end, name, "")
    seg = idaapi.segment_t()
    seg.startEA = start
    seg.endEA   = end
    seg.bitness = 1 # 32-bit
    idaapi.add_segm_ex(seg, name, segmentType, 0)
    # AddSeg(start, end, 0, 1, idaapi.saAbs, idaapi.scPub)
    offset = li.tell()
    # li.file2base(offset, start, end, 0)
    data = li.read(end-start)

    if modificationType == 2:
        byteswapped = bytearray([0]) * len(data)
        byteswapped[0::2] = data[1::2]
        byteswapped[1::2] = data[0::2]
        idaapi.mem2base(str(byteswapped), start, end)
    else:
        idaapi.mem2base(data, start, end)

# -----------------------------------------------------------------------

def load_file(li, neflags, format):

    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """

    if not format == FILE_FORMAT_NAME:
       warning("Unknown format name: '%s'" % format)
       return 0

    idaapi.set_processor_type("sh3b", SETPROC_LOADER)

    load_sh2_data(li);
    print "Load OK"
    return 1

def load_header(li):
    li.seek(0)
    header = li.read(3)
    endian = byteAt(li,3)
    headerVersion = dwordAt(li,0)
    fullFileSize = dwordAt(li,0)
    if headerVersion >= 2:
        videoFrameCount = dwordAt(li,0)
        videoLocation = dwordAt(li,0)
    else:
        warning("header version not >=2, this is untested")
    return 1

def StateCheckRetrieveHeader(li, expectedTitle, skipContent=True):
    title = li.read(4)
    if not title == expectedTitle:
        error("Expected Title to be:"+expectedTitle+" but got:"+str(title))
        return 0
    sectionVersion = dwordAt(li,0)
    sectionSize = dwordAt(li,0)
    if skipContent:
        li.seek(li.tell()+sectionSize)
    return sectionSize

def Vdp2LoadState(li, size):
    # Skip registers
    initial_position_in_yss = li.tell()
    li.seek(li.tell()+288)
    # VDP2 RAM
    create_load_seg(li, 0x25E00000, 0x25E80000, 1, "VDP2RAM", "DATA")
    create_load_seg(li, 0x25F00000, 0x25F01000, 2, "VDP2CRAM", "DATA")
    li.seek(li.tell()+(size-(li.tell()-initial_position_in_yss)))

def Vdp1LoadState(li, size):
    # Skip registers
    initial_position_in_yss = li.tell()
    li.seek(li.tell()+52)
    # VDP1 RAM
    create_load_seg(li, 0x25C00000, 0x25C80000, 1, "VDP1RAM", "DATA")
    li.seek(li.tell()+(size-(li.tell()-initial_position_in_yss)))

def SH2LoadState(li, isSlave, size):
    if isSlave:
        li.seek(li.tell()+1)
    # Skip registers
    initial_position_in_yss = li.tell()
    li.seek(li.tell()+88)
    programCounter = dwordAt(li,0)
    li.seek(li.tell()+(size-(li.tell()-initial_position_in_yss)))
    return programCounter

def make_vector(addr, name):
    idaapi.doDwrd(addr, 4)
    idaapi.create_insn(addr)
    idaapi.add_func(addr, idaapi.BADADDR);
    idaapi.add_cref(addr, addr, idaapi.fl_CF);
    if len(name)>0:
        idaapi.set_name(addr, name)
    return 1

def identify_vector_table():
    # MSH2 vector table
    for i in range(0x06000000,0x06000200,4):
        make_vector(i, "msh2_vector_"+str(i))

    # SSH2 vector table
    for i in range(0x06000400,0x06000600,4):
        make_vector(i, "ssh2_vector_"+str(i))
    return 1

def find_bios_funcs():
    make_ascii_string(0x06000200, 16, ASCSTR_C)
    doByte(0x06000210, 36)
    make_vector(0x06000234, "")
    make_vector(0x06000238, "")
    make_vector(0x0600023C, "")
    make_ascii_string(0x06000240, 4, ASCSTR_C)
    make_ascii_string(0x06000244, 4, ASCSTR_C)
    doDwrd(0x06000248, 4)
    doDwrd(0x0600024C, 4)
    make_vector(0x06000250, "")
    doDwrd(0x06000264, 4)
    make_vector(0x06000268, "")
    make_vector(0x0600026C, "bios_run_cd_player")
    make_vector(0x06000270, "")
    make_vector(0x06000274, "bios_is_mpeg_card_present")
    doDwrd(0x06000278, 4)
    doDwrd(0x0600027C, 4)
    make_vector(0x06000280, "")
    make_vector(0x06000284, "")
    make_vector(0x06000288, "")
    make_vector(0x0600028C, "")
    doDwrd(0x06000290, 4)
    doDwrd(0x06000294, 4)
    make_vector(0x06000298, "bios_get_mpeg_rom")
    make_vector(0x0600029C, "")
    doDwrd(0x060002A0, 4)
    doDwrd(0x060002A4, 4)
    doDwrd(0x060002A8, 4)
    doDwrd(0x060002AC, 4)
    make_vector(0x060002B0, "")
    doDwrd(0x060002B4, 4)
    doDwrd(0x060002B8, 4)
    doDwrd(0x060002BC, 4)
    doDwrd(0x060002C0, 4)

    # for (i = 0x060002C4; i < 0x06000324; i+=4)
    for i in range(0x060002C4,0x06000324,4):
        make_vector(i, "")
    set_name(0x06000300, "bios_set_scu_interrupt")
    set_name(0x06000304, "bios_get_scu_interrupt")
    set_name(0x06000310, "bios_set_sh2_interrupt")
    set_name(0x06000314, "bios_get_sh2_interrupt")
    set_name(0x06000320, "bios_set_clock_speed")
    doDwrd(0x06000324, 4)
    set_name(0x06000324, "bios_get_clock_speed")
    # for (i = 0x06000328; i < 0x06000348; i+=4)
    for i in range(0x06000328,0x06000348,4):
        make_vector(i, "")
    set_name(0x06000340, "bios_set_scu_interrupt_mask")
    set_name(0x06000344, "bios_change_scu_interrupt_mask")
    doDwrd(0x06000348, 4)
    set_name(0x06000348, "bios_get_scu_interrupt_mask")
    make_vector(0x0600034C, "")
    doDwrd(0x06000350, 4)
    doDwrd(0x06000354, 4)
    doDwrd(0x06000358, 4)
    doDwrd(0x0600035C, 4)
    for i in range(0x06000360,0x06000380,4):
        make_vector(i, "")
    doByte(0x06000380, 16)
    doWord(0x06000390, 16)
    doDwrd(0x060003A0, 32)
    make_ascii_string(0x060003C0, 0x40, ASCSTR_C)
    add_func(0x06000600, BADADDR)
    add_func(0x06000646, BADADDR)
    make_ascii_string(0x0600065C, 0x4, ASCSTR_C)
    add_func(0x06000678, BADADDR)
    add_func(0x0600067C, BADADDR)
    add_func(0x06000690, BADADDR)
    doDwrd(0x06000A80, 0x80);
    return 1

def find_parse_ip(li, ea, parsecode):
    # TODO check memory for SEGA SATURN string
    # segaSaturn = li.read(16)
    # warning(segaSaturn+' '+str(li.tell()))
    make_ascii_string(ea, 16, ASCSTR_C)
    make_ascii_string(ea+0x10, 16, ASCSTR_C)
    make_ascii_string(ea+0x20, 10, ASCSTR_C)
    make_ascii_string(ea+0x2A, 6, ASCSTR_C)
    make_ascii_string(ea+0x30, 8, ASCSTR_C)
    make_ascii_string(ea+0x38, 8, ASCSTR_C)
    make_ascii_string(ea+0x40, 10, ASCSTR_C)
    make_ascii_string(ea+0x4A, 6, ASCSTR_C)
    make_ascii_string(ea+0x50, 16, ASCSTR_C)
    make_ascii_string(ea+0x60, 0x70, ASCSTR_C)
    doByte(ea+0xD0, 16)
    doDwrd(ea+0xE0, 4)
    doDwrd(ea+0xE4, 4)
    doDwrd(ea+0xE8, 4)
    doDwrd(ea+0xEC, 4)
    doDwrd(ea+0xF0, 4)
    add_func(get_long(ea+0xF0), BADADDR)
    doDwrd(ea+0xF4, 4)
    doDwrd(ea+0xF8, 4)
    doDwrd(ea+0xFC, 4)
    if parsecode:
        add_func(ea+0x100, BADADDR)
    return 1
