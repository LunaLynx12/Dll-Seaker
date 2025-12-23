"""
Relocation Analyzer - Analyze PE relocations
"""

from typing import Dict, List, Any, Optional
import pefile


class RelocationAnalyzer:
    """Analyze relocation entries in PE files"""
    
    RELOCATION_TYPES = {
        0: 'IMAGE_REL_BASED_ABSOLUTE',
        1: 'IMAGE_REL_BASED_HIGH',
        2: 'IMAGE_REL_BASED_LOW',
        3: 'IMAGE_REL_BASED_HIGHLOW',
        4: 'IMAGE_REL_BASED_HIGHADJ',
        5: 'IMAGE_REL_BASED_MACHINE_SPECIFIC_5',
        6: 'IMAGE_REL_BASED_RESERVED',
        7: 'IMAGE_REL_BASED_MACHINE_SPECIFIC_7',
        8: 'IMAGE_REL_BASED_MACHINE_SPECIFIC_8',
        9: 'IMAGE_REL_BASED_MACHINE_SPECIFIC_9',
        10: 'IMAGE_REL_BASED_DIR64',
    }
    
    def __init__(self, pe: pefile.PE):
        """Initialize relocation analyzer"""
        self.pe = pe
    
    def analyze(self) -> Dict[str, Any]:
        """Analyze relocations"""
        if not self.pe:
            return {'relocations': [], 'count': 0}
        
        relocations = []
        type_counts = {}
        
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC'):
                for reloc in self.pe.DIRECTORY_ENTRY_BASERELOC:
                    virtual_address = reloc.struct.VirtualAddress
                    size = reloc.struct.SizeOfBlock
                    
                    entries = []
                    for entry in reloc.entries:
                        reloc_type = entry.type
                        offset = entry.rva
                        
                        type_name = self.RELOCATION_TYPES.get(reloc_type, f'UNKNOWN_{reloc_type}')
                        type_counts[type_name] = type_counts.get(type_name, 0) + 1
                        
                        entries.append({
                            'type': reloc_type,
                            'type_name': type_name,
                            'offset': hex(offset),
                            'rva': hex(offset)
                        })
                    
                    relocations.append({
                        'virtual_address': hex(virtual_address),
                        'size': hex(size),
                        'entry_count': len(entries),
                        'entries': entries
                    })
        except Exception:
            pass
        
        return {
            'relocations': relocations,
            'count': len(relocations),
            'total_entries': sum(r['entry_count'] for r in relocations),
            'type_counts': type_counts,
            'has_relocations': len(relocations) > 0,
            'aslr_compatible': self._check_aslr_compatibility()
        }
    
    def _check_aslr_compatibility(self) -> bool:
        """Check if DLL is ASLR compatible"""
        if not self.pe:
            return False
        
        try:
            # Check if DYNAMIC_BASE or HIGH_ENTROPY_VA is set
            dll_chars = self.pe.OPTIONAL_HEADER.DllCharacteristics
            return bool(dll_chars & 0x0040) or bool(dll_chars & 0x0080)
        except:
            return False

