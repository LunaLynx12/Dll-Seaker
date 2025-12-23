"""
Constants for DLL Seeker
"""

# Machine types
MACHINE_TYPES = {
    0x14c: 'i386',
    0x8664: 'x86-64',
    0x1c0: 'ARM',
    0xaa64: 'ARM64',
    0x1c4: 'ARMNT',
    0xebc: 'EFI Byte Code',
    0x200: 'IA64',
    0x9041: 'M32R',
    0x266: 'MIPS16',
    0x366: 'MIPSFPU',
    0x466: 'MIPSFPU16',
    0x1f0: 'PowerPC',
    0x1f1: 'PowerPCFP',
    0x166: 'R4000',
    0x5032: 'RISCV32',
    0x5064: 'RISCV64',
    0x5128: 'RISCV128',
    0x1a2: 'SH3',
    0x1a3: 'SH3DSP',
    0x1a6: 'SH4',
    0x1a8: 'SH5',
    0x1c2: 'THUMB',
    0x169: 'WCEMIPSV2'
}

# Characteristics flags
CHARACTERISTICS_FLAGS = {
    0x0001: 'RELOCS_STRIPPED',
    0x0002: 'EXECUTABLE_IMAGE',
    0x0004: 'LINE_NUMS_STRIPPED',
    0x0008: 'LOCAL_SYMS_STRIPPED',
    0x0010: 'AGGRESSIVE_WS_TRIM',
    0x0020: 'LARGE_ADDRESS_AWARE',
    0x0080: 'BYTES_REVERSED_LO',
    0x0100: '32BIT_MACHINE',
    0x0200: 'DEBUG_STRIPPED',
    0x0400: 'REMOVABLE_RUN_FROM_SWAP',
    0x0800: 'NET_RUN_FROM_SWAP',
    0x1000: 'SYSTEM',
    0x2000: 'DLL',
    0x4000: 'UP_SYSTEM_ONLY',
    0x8000: 'BYTES_REVERSED_HI'
}

# DLL characteristics flags
DLL_CHARACTERISTICS_FLAGS = {
    0x0040: 'HIGH_ENTROPY_VA',
    0x0080: 'DYNAMIC_BASE',
    0x0100: 'FORCE_INTEGRITY',
    0x0200: 'NX_COMPAT',
    0x0400: 'NO_ISOLATION',
    0x0800: 'NO_SEH',
    0x1000: 'NO_BIND',
    0x2000: 'APPCONTAINER',
    0x4000: 'WDM_DRIVER',
    0x8000: 'GUARD_CF',
    0x0002: 'TERMINAL_SERVER_AWARE'
}

# Subsystems
SUBSYSTEMS = {
    0: 'UNKNOWN',
    1: 'NATIVE',
    2: 'WINDOWS_GUI',
    3: 'WINDOWS_CUI',
    5: 'OS2_CUI',
    7: 'POSIX_CUI',
    9: 'WINDOWS_CE_GUI',
    10: 'EFI_APPLICATION',
    11: 'EFI_BOOT_SERVICE_DRIVER',
    12: 'EFI_RUNTIME_DRIVER',
    13: 'EFI_ROM',
    14: 'XBOX',
    16: 'WINDOWS_BOOT_APPLICATION'
}

# Section characteristics
SECTION_CHARACTERISTICS = {
    0x00000020: 'IMAGE_SCN_CNT_CODE',
    0x00000040: 'IMAGE_SCN_CNT_INITIALIZED_DATA',
    0x00000080: 'IMAGE_SCN_CNT_UNINITIALIZED_DATA',
    0x00000200: 'IMAGE_SCN_LNK_INFO',
    0x00000800: 'IMAGE_SCN_LNK_REMOVE',
    0x00001000: 'IMAGE_SCN_LNK_COMDAT',
    0x00004000: 'IMAGE_SCN_GPREL',
    0x00008000: 'IMAGE_SCN_MEM_PURGEABLE',
    0x00010000: 'IMAGE_SCN_MEM_16BIT',
    0x00020000: 'IMAGE_SCN_MEM_LOCKED',
    0x00040000: 'IMAGE_SCN_MEM_PRELOAD',
    0x00100000: 'IMAGE_SCN_ALIGN_1BYTES',
    0x00200000: 'IMAGE_SCN_ALIGN_2BYTES',
    0x00300000: 'IMAGE_SCN_ALIGN_4BYTES',
    0x00400000: 'IMAGE_SCN_ALIGN_8BYTES',
    0x00500000: 'IMAGE_SCN_ALIGN_16BYTES',
    0x00600000: 'IMAGE_SCN_ALIGN_32BYTES',
    0x00700000: 'IMAGE_SCN_ALIGN_64BYTES',
    0x00800000: 'IMAGE_SCN_ALIGN_128BYTES',
    0x00900000: 'IMAGE_SCN_ALIGN_256BYTES',
    0x00A00000: 'IMAGE_SCN_ALIGN_512BYTES',
    0x00B00000: 'IMAGE_SCN_ALIGN_1024BYTES',
    0x00C00000: 'IMAGE_SCN_ALIGN_2048BYTES',
    0x00D00000: 'IMAGE_SCN_ALIGN_4096BYTES',
    0x00E00000: 'IMAGE_SCN_ALIGN_8192BYTES',
    0x01000000: 'IMAGE_SCN_LNK_NRELOC_OVFL',
    0x02000000: 'IMAGE_SCN_MEM_DISCARDABLE',
    0x04000000: 'IMAGE_SCN_MEM_NOT_CACHED',
    0x08000000: 'IMAGE_SCN_MEM_NOT_PAGED',
    0x10000000: 'IMAGE_SCN_MEM_SHARED',
    0x20000000: 'IMAGE_SCN_MEM_EXECUTE',
    0x40000000: 'IMAGE_SCN_MEM_READ',
    0x80000000: 'IMAGE_SCN_MEM_WRITE'
}

# Resource types
RESOURCE_TYPES = {
    1: 'cursor',
    2: 'bitmap',
    3: 'icon',
    4: 'menu',
    5: 'dialog',
    6: 'string',
    7: 'fontdir',
    8: 'font',
    9: 'accelerator',
    10: 'rcdata',
    11: 'messagetable',
    12: 'group_cursor',
    14: 'group_icon',
    16: 'version',
    17: 'dlginclude',
    19: 'plugplay',
    20: 'vxd',
    21: 'anicursor',
    22: 'aniicon',
    23: 'html',
    24: 'manifest'
}

# Default configuration
DEFAULT_CONFIG = {
    'max_string_length': 1000,
    'min_string_length': 4,
    'max_dependency_depth': 5,
    'enable_caching': True,
    'chunk_size': 8192
}

