"""
YARA Scanner - Optional YARA rule matching
"""

from typing import Dict, List, Any, Optional
from pathlib import Path


try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YARAScanner:
    """Scan DLLs with YARA rules"""
    
    def __init__(self):
        """Initialize YARA scanner"""
        self.available = YARA_AVAILABLE
        if not YARA_AVAILABLE:
            raise ImportError(
                "yara-python not installed. Install with: pip install yara-python\n"
                "Note: YARA also requires the YARA library to be installed on your system."
            )
    
    def scan_file(self, file_path: str, rules_path: str) -> List[Dict[str, Any]]:
        """Scan a file with YARA rules"""
        if not self.available:
            return []
        
        try:
            rules = yara.compile(rules_path)
            matches = rules.match(file_path)
            
            results = []
            for match in matches:
                results.append({
                    'rule': match.rule,
                    'tags': list(match.tags),
                    'strings': [
                        {
                            'identifier': s.identifier,
                            'offset': s.offset,
                            'data': s.instances[0].matched_data.decode('utf-8', errors='replace') if s.instances else ''
                        }
                        for s in match.strings
                    ],
                    'meta': match.meta
                })
            
            return results
        except Exception as e:
            return [{'error': str(e)}]
    
    def scan_data(self, data: bytes, rules_path: str) -> List[Dict[str, Any]]:
        """Scan binary data with YARA rules"""
        if not self.available:
            return []
        
        try:
            rules = yara.compile(rules_path)
            matches = rules.match(data=data)
            
            results = []
            for match in matches:
                results.append({
                    'rule': match.rule,
                    'tags': list(match.tags),
                    'strings': [
                        {
                            'identifier': s.identifier,
                            'offset': s.offset,
                            'data': s.instances[0].matched_data.decode('utf-8', errors='replace') if s.instances else ''
                        }
                        for s in match.strings
                    ],
                    'meta': match.meta
                })
            
            return results
        except Exception as e:
            return [{'error': str(e)}]

