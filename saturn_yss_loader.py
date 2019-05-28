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
    create_load_seg(li, 0x06000000, 0x06100000, 2, "HWRAM", "DATA")
    create_load_seg(li, 0x00200000, 0x00300000, 2, "LWRAM", "DATA")

    identify_vector_table()
    find_bios_funcs()
    find_parse_ip(li, 0x06000C00, False)
    find_parse_ip(li, 0x06002000, True)
    add_untested()
    idaapi.jumpto(programCounter)
    plan_to_apply_idasgn('SegaBasicLibrary_6.01_Saturn.sig')
    plan_to_apply_idasgn('SegaGraphicsLibrary_3.02J_Saturn.sig')
    plan_to_apply_idasgn('SegaSaturnSGLPlusCPK.sig')
    return 1

# -----------------------------------------------------------------------
def create_load_seg(li, start, end, modificationType,name, segmentType="CODE"):
    # add_segm(0, start, end, name, "")
    seg = idaapi.segment_t()
    seg.startEA = start
    seg.endEA   = end
    seg.bitness = 1 # 32-bit
    idaapi.add_segm_ex(seg, name, "", 0)
    # AddSeg(start, end, 0, 1, idaapi.saAbs, idaapi.scPub)
    offset = li.tell()
    # li.file2base(offset, start, end, 0)
    data = li.read(end-start)

    # put_dword

    if modificationType == 2:
        byteswapped = bytearray([0]) * len(data)
        byteswapped[0::2] = data[1::2]
        byteswapped[1::2] = data[0::2]
        # idaapi.mem2base(str(byteswapped), start, end)
        for i in range(0,end-start):
            put_byte(start+i, byteswapped[i])
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

# As far as I can see most of these match up for most games but it may depend the version of saturn sdk
def add_untested():
    allAbsAddresses=[(0x060ffc00, "_EventTop"),
(0x060ffc04, "_EventLast"),
(0x060ffc08, "_EventNow"),
(0x060ffc0c, "_EventCount"),
(0x060ffc0e, "_WorkCount"),
(0x060ffc10, "_MainMode"),
(0x060ffc11, "_SubMode"),
(0x060ffc12, "_SynchConst"),
(0x060ffc13, "_SynchCount"),
(0x060ffc14, "_UserFunction"),
(0x060ffc18, "_TransCount"),
(0x060ffc1a, "_TransRequest"),
(0x060ffc1b, "_PauseFlag"),
(0x060ffc1c, "_mtptr"),
(0x060ffc20, "_MatrixCount"),
(0x060ffc22, "_IntCount"),
(0x060ffc24, "_MsPbufPtr"),
(0x060ffc28, "_SlPbufPtr"),
(0x060ffc2c, "_SpritePtr"),
(0x060ffc30, "_MsSdataPtr"),
(0x060ffc34, "_SlSdataPtr"),
(0x060ffc38, "_ZbufPtr"),
(0x060ffc3c, "_FormTbl"),
(0x060ffc40, "_SprbufBias"),
(0x060ffc44, "_ComRdPtr"),
(0x060ffc48, "_ComWrPtr"),
(0x060ffc58, "_SlLightVector"),
(0x060ffc64, "_ColorOffset"),
(0x060ffc68, "_MsScreenDist"),
(0x060ffc6c, "_SlScreenDist"),
(0x060ffc70, "_MsZlimit"),
(0x060ffc72, "_MsWindowNumber"),
(0x060ffc74, "_TotalPolygons"),
(0x060ffc78, "_MsScreenLeft"),
(0x060ffc7a, "_MsScreenTop"),
(0x060ffc7c, "_MsScreenRight"),
(0x060ffc80, "_MsScreenSizeX"),
(0x060ffc84, "_MsWindowSizeX"),
(0x060ffc86, "_MsWindowSizeY"),
(0x060ffc88, "_MXPolygons"),
(0x060ffc8c, "_FrameSizeX"),
(0x060ffc8e, "_FrameSizeY"),
(0x060ffc90, "_MsWinXAdder"),
(0x060ffc96, "_SlWinYAdder"),
(0x060ffc98, "_MsClipXAdder"),
(0x060ffc9a, "_MsClipYAdder"),
(0x060ffc9c, "_SlClipXAdder"),
(0x060ffca0, "_SlZlimit"),
(0x060ffca2, "_WinPtr"),
(0x060ffca6, "_DMAEndFlag"),
(0x060ffca7, "_gxMatrixCount"),
(0x060ffca8, "_DMASetFlag"),
(0x060ffca9, "_SlWindowNumber"),
(0x060ffcac, "_MsZdpsfcnt"),
(0x060ffcad, "_SlZdpsfcnt"),
(0x060ffcb0, "_Resolution"),
(0x060ffcb1, "_NbPCMBf"),
(0x060ffcb2, "_PCMBufFlag"),
(0x060ffcb6, "_FRT_Count"),
(0x060ffcb8, "_SCUMC_ID"),
(0x060ffcba, "_DMASt_CPU1"),
(0x060ffcbc, "_DMASt_SCU1"),
(0x060ffcbd, "_DMASt_SCU2"),
(0x060ffcbe, "_ENH_ColMode"),
(0x060ffcbf, "_ENH_ColBank"),
(0x060ffcc2, "_VDP2_EXTEN"),
(0x060ffcca, "_VDP2_VCNT"),
(0x060ffccc, "_RotTransFlag"),
(0x060ffcce, "_VDP2_RAMCTL"),
(0x060ffcd0, "_VDP2_CYCA0L"),
(0x060ffcd2, "_VDP2_CYCA0U"),
(0x060ffcd4, "_VDP2_CYCA1L"),
(0x060ffcd6, "_VDP2_CYCA1U"),
(0x060ffcde, "_VDP2_CYCB1U"),
(0x060ffce0, "_VDP2_BGON"),
(0x060ffce2, "_VDP2_MZCTL"),
(0x060ffce4, "_VDP2_SFSEL"),
(0x060ffce6, "_VDP2_SFCODE"),
(0x060ffce8, "_VDP2_CHCTLA"),
(0x060ffcea, "_VDP2_CHCTLB"),
(0x060ffcee, "_VDP2_BMPNB"),
(0x060ffcf0, "_VDP2_PNCN0"),
(0x060ffcf2, "_VDP2_PNCN1"),
(0x060ffcf4, "_VDP2_PNCN2"),
(0x060ffcf8, "_VDP2_PNCR"),
(0x060ffcfa, "_VDP2_PLSZ"),
(0x060ffcfc, "_VDP2_MPOFN"),
(0x060ffcfe, "_VDP2_MPOFR"),
(0x060ffd00, "_VDP2_MPABN0"),
(0x060ffd04, "_VDP2_MPABN1"),
(0x060ffd06, "_VDP2_MPCDN1"),
(0x060ffd0a, "_VDP2_MPCDN2"),
(0x060ffd0c, "_VDP2_MPABN3"),
(0x060ffd0e, "_VDP2_MPCDN3"),
(0x060ffd10, "_VDP2_MPABRA"),
(0x060ffd14, "_VDP2_MPEFRA"),
(0x060ffd16, "_VDP2_MPGHRA"),
(0x060ffd18, "_VDP2_MPIJRA"),
(0x060ffd1a, "_VDP2_MPKLRA"),
(0x060ffd1c, "_VDP2_MPMNRA"),
(0x060ffd1e, "_VDP2_MPOPRA"),
(0x060ffd22, "_VDP2_MPCDRB"),
(0x060ffd24, "_VDP2_MPEFRB"),
(0x060ffd2e, "_VDP2_MPOPRB"),
(0x060ffd30, "_Nbg0_PosX"),
(0x060ffd30, "_VDP2_SCXIN0"),
(0x060ffd30, "_VDP2_SCXN0"),
(0x060ffd32, "_VDP2_SCXDN0"),
(0x060ffd34, "_VDP2_SCYIN0"),
(0x060ffd34, "_VDP2_SCYN0"),
(0x060ffd38, "_VDP2_ZMXN0"),
(0x060ffd3a, "_VDP2_ZMXDN0"),
(0x060ffd3c, "_VDP2_ZMYN0"),
(0x060ffd3e, "_VDP2_ZMYDN0"),
(0x060ffd40, "_Nbg1_PosX"),
(0x060ffd40, "_VDP2_SCXIN1"),
(0x060ffd40, "_VDP2_SCXN1"),
(0x060ffd44, "_Nbg1_PosY"),
(0x060ffd44, "_VDP2_SCYIN1"),
(0x060ffd44, "_VDP2_SCYN1"),
(0x060ffd48, "_VDP2_ZMXIN1"),
(0x060ffd48, "_VDP2_ZMXN1"),
(0x060ffd4a, "_VDP2_ZMXDN1"),
(0x060ffd4c, "_VDP2_ZMYIN1"),
(0x060ffd4c, "_VDP2_ZMYN1"),
(0x060ffd4e, "_VDP2_ZMYDN1"),
(0x060ffd50, "_VDP2_SCXN2"),
(0x060ffd52, "_VDP2_SCYN2"),
(0x060ffd54, "_VDP2_SCXN3"),
(0x060ffd56, "_VDP2_SCYN3"),
(0x060ffd58, "_VDP2_ZMCTL"),
(0x060ffd64, "_VDP2_LSTA1"),
(0x060ffd68, "_VDP2_LCTA"),
(0x060ffd6c, "_VDP2_BKTA"),
(0x060ffd70, "_VDP2_RPMD"),
(0x060ffd72, "_VDP2_RPRCTL"),
(0x060ffd76, "_VDP2_KTAOF"),
(0x060ffd78, "_VDP2_OVPNRA"),
(0x060ffd7a, "_VDP2_OVPNRB"),
(0x060ffd80, "_VDP2_WPSX0"),
(0x060ffd82, "_VDP2_WPSY0"),
(0x060ffd84, "_VDP2_WPEX0"),
(0x060ffd86, "_VDP2_WPEY0"),
(0x060ffd88, "_VDP2_WPSX1"),
(0x060ffd8a, "_VDP2_WPSY1"),
(0x060ffd8c, "_VDP2_WPEX1"),
(0x060ffd8e, "_VDP2_WPEY1"),
(0x060ffd90, "_VDP2_WCTLA"),
(0x060ffd92, "_VDP2_WCTLB"),
(0x060ffd94, "_VDP2_WCTLC"),
(0x060ffd96, "_VDP2_WCTLD"),
(0x060ffd98, "_VDP2_LWTA0"),
(0x060ffd9c, "_VDP2_LWTA1"),
(0x060ffda0, "_VDP2_SPCTL"),
(0x060ffda2, "_VDP2_SDCTL"),
(0x060ffda4, "_VDP2_CRAOFA"),
(0x060ffda6, "_VDP2_CRAOFB"),
(0x060ffdaa, "_VDP2_SFPRMD"),
(0x060ffdac, "_VDP2_CCCTL"),
(0x060ffdae, "_VDP2_SFCCMD"),
(0x060ffdb0, "_VDP2_PRISA"),
(0x060ffdb2, "_VDP2_PRISB"),
(0x060ffdb6, "_VDP2_PRISD"),
(0x060ffdbc, "_VDP2_PRIR"),
(0x060ffdc0, "_VDP2_CCRSA"),
(0x060ffdc2, "_VDP2_CCRSB"),
(0x060ffdc6, "_VDP2_CCRSD"),
(0x060ffdc8, "_VDP2_CCRNA"),
(0x060ffdca, "_VDP2_CCRNB"),
(0x060ffdce, "_VDP2_CCRLB"),
(0x060ffdd0, "_VDP2_CLOFEN"),
(0x060ffdd4, "_VDP2_COAR"),
(0x060ffdde, "_VDP2_COBB"),
(0x060ffde0, "_VDP2_PRMSIZE"),
(0x060ffde8, "_nbg1_char_adr"),
(0x060ffdec, "_nbg2_char_adr"),
(0x060ffdf0, "_nbg3_char_adr"),
(0x060ffdf4, "_ra_char_adr"),
(0x060ffdf8, "_rb_char_adr"),
(0x060ffdfc, "_nbg0_page_adr"),
(0x060ffe04, "_nbg2_page_adr"),
(0x060ffe08, "_nbg3_page_adr"),
(0x060ffe0c, "_ra_page_adr"),
(0x060ffe10, "_rb_page_adr"),
(0x060ffe1c, "_RotScrParA"),
(0x060ffe84, "_RotScrParB"),
(0x060ffeec, "_Nbg2_PosX"),
(0x060ffef0, "_Nbg2_PosY"),
(0x060ffef4, "_Nbg3_PosX"),
(0x060ffef8, "_Nbg3_PosY"),
(0x060ffefc, "_Window1_data"),
(0x060ffeff, "_Window1_dpscnt"),
(0x060fff03, "_Window2_dpscnt"),
(0x060fff04, "_End_Sprite"),
(0x060fff08, "_Window1_Left"),
(0x060fff0a, "_Window1_Top"),
(0x060fff0c, "_Window2_Left"),
(0x060fff0e, "_Window2_Top"),
(0x060fff10, "_Window1_Right"),
(0x060fff12, "_Window1_Bottom"),
(0x060fff14, "_Window2_Right"),
(0x060fff16, "_Window2_Bottom"),
(0x060fff1a, "_FrameXOffset"),
(0x060fff1c, "_Win2Zlimit"),
(0x060fff28, "_Center1_data"),
(0x060fff2c, "_Center2_data"),
(0x060fff30, "_SlWindowSizeX"),
(0x060fff34, "_Center1_PosX"),
(0x060fff36, "_Center1_PosY"),
(0x060fff38, "_Center2_PosX"),
(0x060fff3c, "_RandWork"),
(0x060fff44, "_VRN0"),
(0x060fff45, "_VRE0"),
(0x060fff46, "_DRCR0"),
(0x060fff47, "_DMAOR"),
(0x060fff48, "_SAR0"),
(0x060fff50, "_TCR0"),
(0x060fff58, "_VRN1"),
(0x060fff5a, "_DRCR1"),
(0x060fff5c, "_SAR1"),
(0x060fff60, "_DAR1"),
(0x060fff64, "_TCR1"),
(0x060fff68, "_CHCR1"),
(0x060fff6c, "_PCMPtr"),
(0x060fff70, "_SoundPtr"),
(0x060fff74, "_SndTrnsFunc"),
(0x060fff78, "_SmpcComWtPtr"),
(0x060fff7c, "_SmpcComRdPtr"),
(0x060fff80, "_SmpcResOffset"),
(0x060fff8c, "_SmpcPerPointer"),
(0x060fff90, "_SmpcIntBackData"),
(0x060fff94, "_SmpcMemSetData"),
(0x060fff98, "_SmpcTimeSetData"),
(0x060fffa0, "_SmpcSemaphore"),
(0x060fffa1, "_SmpcChangeFlag"),
(0x060fffa2, "_SmpcControlFlag"),
(0x060fffa4, "_SmpcComNumber"),
(0x060fffa5, "_SmpcIntBackCom"),
(0x060fffa7, "_SmpcPerCommand"),
(0x060fffa8, "_SmpcPortDir1"),
(0x060fffa9, "_SmpcPortDir2"),
(0x060fffaa, "_SmpcPortSelect"),
(0x060fffab, "_SmpcPortExt"),
(0x06000000, "BootROMBIOSfunctions"),
(0x06000800, "SlaveCPUStackArea"),
(0x06001000, "MasterCPUDefaultStack"),
(0x06004000, "UserArea"),
(0x060C0000, "SortList"),
(0x060C549C, "TransList"),
(0x060C558C, "ZBuffer"),
(0x060C578C, "ZBuffer2"),
(0x06000C30, "GameBuildDate"),
]
    for address,name in allAbsAddresses:
        set_name(address, name)
