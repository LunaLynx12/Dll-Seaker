"""
Debug Extractor - Extract debug information
"""

from typing import Dict, List, Any, Optional
import pefile


class DebugExtractor:
    """Extract debug information from PE files"""
    
    def __init__(self, pe: pefile.PE):
        """Initialize debug extractor"""
        self.pe = pe
    
    def extract(self) -> Dict[str, Any]:
        """Extract debug information"""
        if not self.pe:
            return {'debug_info': [], 'count': 0}
        
        debug_info = []
        
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_DEBUG'):
                for dbg in self.pe.DIRECTORY_ENTRY_DEBUG:
                    debug_entry = {
                        'characteristics': hex(dbg.struct.Characteristics),
                        'timestamp': dbg.struct.TimeDateStamp,
                        'timestamp_readable': self._format_timestamp(dbg.struct.TimeDateStamp),
                        'major_version': dbg.struct.MajorVersion,
                        'minor_version': dbg.struct.MinorVersion,
                        'type': self._get_debug_type(dbg.struct.Type),
                        'size_of_data': hex(dbg.struct.SizeOfData),
                        'address_of_raw_data': hex(dbg.struct.AddressOfRawData),
                        'pointer_to_raw_data': hex(dbg.struct.PointerToRawData)
                    }
                    
                    # Extract PDB path if available
                    if hasattr(dbg, 'entry') and hasattr(dbg.entry, 'PdbFileName'):
                        try:
                            pdb_path = dbg.entry.PdbFileName.decode('utf-8', errors='replace').rstrip('\x00')
                            debug_entry['pdb_path'] = pdb_path
                        except:
                            pass
                    
                    debug_info.append(debug_entry)
        except Exception:
            pass
        
        return {
            'debug_info': debug_info,
            'count': len(debug_info),
            'has_pdb': any('pdb_path' in d for d in debug_info),
            'pdb_paths': [d.get('pdb_path') for d in debug_info if d.get('pdb_path')]
        }
    
    def _get_debug_type(self, debug_type: int) -> str:
        """Get debug type name"""
        types = {
            0: 'IMAGE_DEBUG_TYPE_UNKNOWN',
            1: 'IMAGE_DEBUG_TYPE_COFF',
            2: 'IMAGE_DEBUG_TYPE_CODEVIEW',
            3: 'IMAGE_DEBUG_TYPE_FPO',
            4: 'IMAGE_DEBUG_TYPE_MISC',
            5: 'IMAGE_DEBUG_TYPE_EXCEPTION',
            6: 'IMAGE_DEBUG_TYPE_FIXUP',
            7: 'IMAGE_DEBUG_TYPE_OMAP_TO_SRC',
            8: 'IMAGE_DEBUG_TYPE_OMAP_FROM_SRC',
            9: 'IMAGE_DEBUG_TYPE_BORLAND',
            10: 'IMAGE_DEBUG_TYPE_RESERVED10',
            11: 'IMAGE_DEBUG_TYPE_CLSID',
            14: 'IMAGE_DEBUG_TYPE_VC_FEATURE',
            16: 'IMAGE_DEBUG_TYPE_POGO',
            17: 'IMAGE_DEBUG_TYPE_ILTCG',
            18: 'IMAGE_DEBUG_TYPE_MPX',
            19: 'IMAGE_DEBUG_TYPE_REPRO',
        }
        return types.get(debug_type, f'UNKNOWN_{debug_type}')
    
    def _format_timestamp(self, timestamp: int) -> str:
        """Format timestamp"""
        from datetime import datetime
        try:
            return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return f'Invalid: {timestamp}'

