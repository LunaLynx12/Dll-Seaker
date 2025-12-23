"""
String Analyzer - Categorize and analyze extracted strings
"""

import re
import base64
import binascii
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from collections import defaultdict


class StringAnalyzer:
    """Analyze and categorize strings from DLL files"""
    
    # Regex patterns for different string types
    PATTERNS = {
        'url': re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        ),
        'ipv4': re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        'ipv6': re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        ),
        'file_path': re.compile(
            r'(?:[A-Za-z]:)?(?:[\\/][\w\s\-\.]+)+[\\/]?',
            re.IGNORECASE
        ),
        'registry_key': re.compile(
            r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)[\\\w\s\-\.]+',
            re.IGNORECASE
        ),
        'guid': re.compile(
            r'\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?',
            re.IGNORECASE
        ),
        'email': re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ),
        'domain': re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        ),
        'md5': re.compile(
            r'\b[0-9a-fA-F]{32}\b'
        ),
        'sha1': re.compile(
            r'\b[0-9a-fA-F]{40}\b'
        ),
        'sha256': re.compile(
            r'\b[0-9a-fA-F]{64}\b'
        ),
        'base64': re.compile(
            r'[A-Za-z0-9+/]{20,}={0,2}'
        ),
        'hex_dump': re.compile(
            r'\b(?:[0-9a-fA-F]{2}[\s:]){8,}[0-9a-fA-F]{2}\b'
        ),
        'command_line': re.compile(
            r'(?:/|-|--)[a-zA-Z0-9_\-]+(?:\s+[^\s]+)?',
            re.IGNORECASE
        ),
        'api_endpoint': re.compile(
            r'/[a-zA-Z0-9_\-/]+(?:\?[^\s<>"{}|\\^`\[\]]+)?',
            re.IGNORECASE
        ),
        'user_agent': re.compile(
            r'[A-Za-z0-9\-]+/[0-9]+\.[0-9]+',
            re.IGNORECASE
        ),
        'version_string': re.compile(
            r'\b\d+\.\d+(?:\.\d+)?(?:\.\d+)?(?:\-[a-zA-Z0-9]+)?\b'
        ),
        'port_number': re.compile(
            r':(?:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\b'
        ),
    }
    
    def __init__(self):
        """Initialize string analyzer"""
        self.categories = defaultdict(list)
        self.statistics = defaultdict(int)
    
    def categorize_string(self, string: str) -> Dict[str, Any]:
        """Categorize a single string"""
        categories = []
        details = {}
        
        # Check each pattern
        for category, pattern in self.PATTERNS.items():
            matches = pattern.findall(string)
            if matches:
                categories.append(category)
                details[category] = matches
        
        # Check for base64 encoding
        if self._is_base64(string):
            if 'base64' not in categories:
                categories.append('base64')
            details['base64_decoded'] = self._try_decode_base64(string)
        
        # Check for hex encoding
        if self._is_hex_encoded(string):
            if 'hex' not in categories:
                categories.append('hex')
            details['hex_decoded'] = self._try_decode_hex(string)
        
        # Check for suspicious patterns
        suspicious = self._check_suspicious(string)
        if suspicious:
            categories.append('suspicious')
            details['suspicious_reasons'] = suspicious
        
        return {
            'string': string,
            'categories': categories,
            'details': details,
            'category_count': len(categories)
        }
    
    def analyze_strings(self, strings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze a list of strings"""
        categorized = []
        category_stats = defaultdict(int)
        all_categories = set()
        
        for string_data in strings:
            string = string_data.get('string', '')
            if not string:
                continue
            
            result = self.categorize_string(string)
            result.update({
                'offset': string_data.get('offset'),
                'section': string_data.get('section'),
                'length': string_data.get('length', len(string))
            })
            
            categorized.append(result)
            
            # Update statistics
            for category in result['categories']:
                category_stats[category] += 1
                all_categories.add(category)
        
        return {
            'categorized_strings': categorized,
            'statistics': dict(category_stats),
            'total_strings': len(categorized),
            'categorized_count': sum(1 for s in categorized if s['categories']),
            'uncategorized_count': sum(1 for s in categorized if not s['categories']),
            'categories_found': sorted(all_categories)
        }
    
    def _is_base64(self, string: str) -> bool:
        """Check if string is base64 encoded"""
        if len(string) < 20:
            return False
        try:
            # Check if it matches base64 pattern and can be decoded
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', string):
                decoded = base64.b64decode(string)
                # Check if decoded data is printable or looks like text
                return len(decoded) > 0 and (decoded.isascii() or len(decoded) < 1000)
        except:
            pass
        return False
    
    def _try_decode_base64(self, string: str) -> Optional[str]:
        """Try to decode base64 string"""
        try:
            decoded = base64.b64decode(string)
            if decoded.isascii():
                return decoded.decode('ascii', errors='replace')
        except:
            pass
        return None
    
    def _is_hex_encoded(self, string: str) -> bool:
        """Check if string is hex encoded"""
        if len(string) < 10:
            return False
        # Remove spaces and colons
        cleaned = re.sub(r'[\s:]', '', string)
        # Check if it's all hex characters and even length
        return len(cleaned) >= 10 and len(cleaned) % 2 == 0 and re.match(r'^[0-9a-fA-F]+$', cleaned)
    
    def _try_decode_hex(self, string: str) -> Optional[str]:
        """Try to decode hex string"""
        try:
            cleaned = re.sub(r'[\s:]', '', string)
            decoded = binascii.unhexlify(cleaned)
            if decoded.isascii():
                return decoded.decode('ascii', errors='replace')
        except:
            pass
        return None
    
    def _check_suspicious(self, string: str) -> List[str]:
        """Check for suspicious patterns"""
        suspicious = []
        
        # Very long strings might be encoded data
        if len(string) > 200:
            suspicious.append('very_long_string')
        
        # High entropy (simple check)
        if self._calculate_simple_entropy(string) > 4.5:
            suspicious.append('high_entropy')
        
        # Contains common obfuscation patterns
        obfuscation_patterns = [
            r'[A-Z]{10,}',  # All caps long strings
            r'[a-z]{20,}',  # All lowercase long strings
            r'[0-9]{15,}',  # Long number sequences
        ]
        for pattern in obfuscation_patterns:
            if re.search(pattern, string):
                suspicious.append('obfuscation_pattern')
                break
        
        # Contains null bytes or control characters
        if '\x00' in string or any(ord(c) < 32 and c not in '\t\n\r' for c in string):
            suspicious.append('control_characters')
        
        return suspicious
    
    def _calculate_simple_entropy(self, string: str) -> float:
        """Calculate simple entropy of string"""
        if not string:
            return 0.0
        
        from collections import Counter
        import math
        
        char_counts = Counter(string)
        length = len(string)
        entropy = 0.0
        
        for count in char_counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def get_strings_by_category(self, analysis: Dict[str, Any], category: str) -> List[Dict[str, Any]]:
        """Get all strings in a specific category"""
        return [
            s for s in analysis['categorized_strings']
            if category in s['categories']
        ]
    
    def get_suspicious_strings(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get all suspicious strings"""
        return self.get_strings_by_category(analysis, 'suspicious')
    
    def export_categorized_strings(self, analysis: Dict[str, Any], output_format: str = 'json') -> str:
        """Export categorized strings to different formats"""
        if output_format == 'json':
            import json
            return json.dumps(analysis, indent=2, default=str)
        elif output_format == 'csv':
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['String', 'Categories', 'Offset', 'Section', 'Length'])
            for s in analysis['categorized_strings']:
                writer.writerow([
                    s['string'][:100],  # Truncate long strings
                    ', '.join(s['categories']),
                    s.get('offset', ''),
                    s.get('section', ''),
                    s.get('length', '')
                ])
            return output.getvalue()
        else:
            return str(analysis)

