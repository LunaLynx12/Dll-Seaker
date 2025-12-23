"""
DLL Seeker - Comprehensive DLL Analysis Tool
Analyzes Windows DLL files and extracts maximum information
"""

import os
import json
import csv
import struct
import re
import math
import hashlib
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from collections import defaultdict, Counter
from functools import lru_cache
from datetime import datetime
from contextlib import contextmanager

import pefile
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

from constants import (
    MACHINE_TYPES, CHARACTERISTICS_FLAGS, DLL_CHARACTERISTICS_FLAGS,
    SUBSYSTEMS, SECTION_CHARACTERISTICS, RESOURCE_TYPES, DEFAULT_CONFIG
)

# Import new analysis modules
from string_analyzer import StringAnalyzer
from malware_detector import MalwareDetector
from dll_comparator import DLLComparator
from graph_generator import GraphGenerator
from performance_profiler import PerformanceProfiler
from relocation_analyzer import RelocationAnalyzer
from debug_extractor import DebugExtractor
from certificate_analyzer import CertificateAnalyzer
from config_manager import ConfigManager
from export_formats import ExportFormats

# Optional YARA
try:
    from yara_scanner import YARAScanner
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class DLLSeeker:
    """Comprehensive DLL analysis and information extraction tool"""
    
    # Class-level dependency cache
    _dependency_cache: Dict[Tuple[str, bool, int], Dict[str, Any]] = {}
    
    def __init__(self, dll_path: str, log_level: int = logging.INFO, enable_cache: bool = True, config: Optional[ConfigManager] = None):
        """Initialize DLL Seeker with a DLL file path"""
        self.dll_path = Path(dll_path)
        if not self.dll_path.exists():
            raise FileNotFoundError(f"DLL file not found: {dll_path}")
        
        self.pe = None
        self.console = Console()
        self.enable_cache = enable_cache
        self._cache = {}
        self.config = config or ConfigManager()
        
        # Initialize analysis modules
        self.string_analyzer = StringAnalyzer()
        self.malware_detector = MalwareDetector()
        self.graph_generator = GraphGenerator()
        self.profiler = PerformanceProfiler(enabled=self.config.get('enable_profiling', False))
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        self._load_pe()
    
    def _load_pe(self):
        """Load and parse the PE file"""
        try:
            # Don't use fast_load=True as it can cause issues with caching
            # The performance gain is minimal and caching handles optimization
            self.pe = pefile.PE(str(self.dll_path))
            self.logger.info(f"Successfully loaded PE file: {self.dll_path}")
        except pefile.PEFormatError as e:
            self.logger.error(f"Invalid PE file format: {e}")
            raise ValueError(f"Invalid PE file format: {e}")
        except Exception as e:
            self.logger.error(f"Error loading PE file: {e}", exc_info=True)
            raise RuntimeError(f"Error loading PE file: {e}")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources"""
        if self.pe:
            self.pe.close()
            self.logger.debug("PE file closed")
        return False
    
    def clear_cache(self):
        """Clear analysis cache"""
        self._cache.clear()
        self.analyze_headers.cache_clear()
        self.analyze_exports.cache_clear()
        self.analyze_imports.cache_clear()
        self.analyze_sections.cache_clear()
        self.logger.debug("Cache cleared")
    
    # ==================== PE HEADER ANALYSIS ====================
    
    @lru_cache(maxsize=1)
    def analyze_headers(self) -> Dict[str, Any]:
        """Analyze PE headers (DOS, PE, COFF)"""
        if not self.pe:
            return {}
        
        try:
            headers = {
                'dos_header': {
                    'magic': hex(self.pe.DOS_HEADER.e_magic),
                    'pe_offset': hex(self.pe.DOS_HEADER.e_lfanew)
                },
                'pe_signature': hex(self.pe.NT_HEADERS.Signature),
                'coff_header': {
                    'machine': hex(self.pe.FILE_HEADER.Machine),
                    'machine_type': self._get_machine_type(self.pe.FILE_HEADER.Machine),
                    'number_of_sections': self.pe.FILE_HEADER.NumberOfSections,
                    'timestamp': self.pe.FILE_HEADER.TimeDateStamp,
                    'timestamp_readable': self._format_timestamp(self.pe.FILE_HEADER.TimeDateStamp),
                    'pointer_to_symbol_table': hex(self.pe.FILE_HEADER.PointerToSymbolTable),
                    'number_of_symbols': self.pe.FILE_HEADER.NumberOfSymbols,
                    'size_of_optional_header': hex(self.pe.FILE_HEADER.SizeOfOptionalHeader),
                    'characteristics': hex(self.pe.FILE_HEADER.Characteristics),
                    'characteristics_flags': self._get_characteristics_flags(self.pe.FILE_HEADER.Characteristics)
                },
                'optional_header': {
                    'magic': hex(self.pe.OPTIONAL_HEADER.Magic),
                    'architecture': '64-bit' if self.pe.OPTIONAL_HEADER.Magic == 0x20b else '32-bit',
                    'entry_point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                    'image_base': hex(self.pe.OPTIONAL_HEADER.ImageBase),
                    'section_alignment': hex(self.pe.OPTIONAL_HEADER.SectionAlignment),
                    'file_alignment': hex(self.pe.OPTIONAL_HEADER.FileAlignment),
                    'size_of_image': hex(self.pe.OPTIONAL_HEADER.SizeOfImage),
                    'size_of_headers': hex(self.pe.OPTIONAL_HEADER.SizeOfHeaders),
                    'subsystem': hex(self.pe.OPTIONAL_HEADER.Subsystem),
                    'subsystem_name': self._get_subsystem_name(self.pe.OPTIONAL_HEADER.Subsystem),
                    'dll_characteristics': hex(self.pe.OPTIONAL_HEADER.DllCharacteristics),
                    'dll_characteristics_flags': self._get_dll_characteristics_flags(self.pe.OPTIONAL_HEADER.DllCharacteristics)
                }
            }
            return headers
        except Exception as e:
            self.logger.error(f"Error analyzing headers: {e}", exc_info=True)
            return {}
    
    def _get_machine_type(self, machine: int) -> str:
        """Get human-readable machine type"""
        return MACHINE_TYPES.get(machine, f'Unknown (0x{machine:x})')
    
    def _get_characteristics_flags(self, characteristics: int) -> List[str]:
        """Get characteristics flags"""
        flags = []
        for flag, name in CHARACTERISTICS_FLAGS.items():
            if characteristics & flag:
                flags.append(name)
        return flags
    
    def _get_dll_characteristics_flags(self, dll_characteristics: int) -> List[str]:
        """Get DLL characteristics flags"""
        flags = []
        for flag, name in DLL_CHARACTERISTICS_FLAGS.items():
            if dll_characteristics & flag:
                flags.append(name)
        return flags
    
    def _get_subsystem_name(self, subsystem: int) -> str:
        """Get subsystem name"""
        return SUBSYSTEMS.get(subsystem, f'Unknown ({subsystem})')
    
    def _format_timestamp(self, timestamp: int) -> str:
        """Format timestamp to readable date"""
        try:
            return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, OSError) as e:
            self.logger.warning(f"Invalid timestamp: {timestamp}, error: {e}")
            return f'Invalid timestamp: {timestamp}'
    
    # ==================== EXPORT ANALYSIS ====================
    
    @lru_cache(maxsize=1)
    def analyze_exports(self) -> Dict[str, Any]:
        """Analyze exported functions and symbols"""
        if not self.pe:
            return {'exports': [], 'count': 0}
        
        try:
            # Try to access the export directory - this will trigger parsing if fast_load=True
            export_dir = self.pe.DIRECTORY_ENTRY_EXPORT
            exports = []
            
            for exp in export_dir.symbols:
                forwarded = bool(exp.forwarder)
                export_info = {
                    'name': exp.name.decode('utf-8', errors='replace') if exp.name else f'Ordinal_{exp.ordinal}',
                    'ordinal': exp.ordinal,
                    'address': hex(exp.address),
                    'forwarded': forwarded,
                    'forwarded_to': exp.forwarder.decode('utf-8', errors='replace') if exp.forwarder else None
                }
                exports.append(export_info)
            
            return {
                'dll_name': export_dir.name.decode('utf-8', errors='replace') if export_dir.name else 'Unknown',
                'exports': exports,
                'count': len(exports)
            }
        except AttributeError:
            # Directory doesn't exist or not parsed yet
            return {'exports': [], 'count': 0}
        except Exception as e:
            self.logger.error(f"Error analyzing exports: {e}", exc_info=True)
            return {'exports': [], 'count': 0}
    
    # ==================== IMPORT ANALYSIS ====================
    
    @lru_cache(maxsize=1)
    def analyze_imports(self) -> Dict[str, Any]:
        """Analyze imported DLLs and functions"""
        if not self.pe:
            return {'imports': {}, 'count': 0}
        
        try:
            # Try to access the import directory - this will trigger parsing if fast_load=True
            import_dir = self.pe.DIRECTORY_ENTRY_IMPORT
            imports_dict = {}
            total_imports = 0
            
            for entry in import_dir:
                dll_name = entry.dll.decode('utf-8', errors='replace')
                functions = []
                
                for imp in entry.imports:
                    func_info = {
                        'name': imp.name.decode('utf-8', errors='replace') if imp.name else f'Ordinal_{imp.ordinal}',
                        'ordinal': imp.ordinal if imp.ordinal else None,
                        'address': hex(imp.address) if imp.address else None,
                        'hint': imp.hint if imp.hint else None
                    }
                    functions.append(func_info)
                    total_imports += 1
                
                imports_dict[dll_name] = {
                    'functions': functions,
                    'count': len(functions)
                }
            
            return {
                'imports': imports_dict,
                'count': total_imports,
                'dll_count': len(imports_dict)
            }
        except AttributeError:
            # Directory doesn't exist or not parsed yet
            return {'imports': {}, 'count': 0}
        except Exception as e:
            self.logger.error(f"Error analyzing imports: {e}", exc_info=True)
            return {'imports': {}, 'count': 0}
    
    def analyze_delay_imports(self) -> Dict[str, Any]:
        """Analyze delay-loaded imports"""
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            return {'delay_imports': [], 'count': 0}
        
        try:
            delay_imports = []
            for entry in self.pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='replace') if entry.dll else 'Unknown'
                functions = []
                
                if hasattr(entry, 'imports'):
                    for imp in entry.imports:
                        func_info = {
                            'name': imp.name.decode('utf-8', errors='replace') if imp.name else f'Ordinal_{imp.ordinal}',
                            'ordinal': imp.ordinal if imp.ordinal else None,
                            'address': hex(imp.address) if imp.address else None
                        }
                        functions.append(func_info)
                
                delay_imports.append({
                    'dll': dll_name,
                    'functions': functions,
                    'count': len(functions)
                })
            
            return {
                'delay_imports': delay_imports,
                'count': sum(d['count'] for d in delay_imports)
            }
        except Exception as e:
            self.logger.warning(f"Error analyzing delay imports: {e}")
            return {'delay_imports': [], 'count': 0}
    
    def analyze_iat(self) -> Dict[str, Any]:
        """Analyze Import Address Table"""
        iat_info = {
            'iat_entries': [],
            'count': 0
        }
        
        if not self.pe:
            return iat_info
        
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        iat_info['iat_entries'].append({
                            'dll': entry.dll.decode('utf-8', errors='replace'),
                            'function': imp.name.decode('utf-8', errors='replace') if imp.name else None,
                            'address': hex(imp.address) if imp.address else None,
                            'ordinal': imp.ordinal if imp.ordinal else None
                        })
        except Exception as e:
            self.logger.warning(f"Error analyzing IAT: {e}")
        
        iat_info['count'] = len(iat_info['iat_entries'])
        return iat_info
    
    # ==================== SECTION ANALYSIS ====================
    
    @lru_cache(maxsize=1)
    def analyze_sections(self) -> Dict[str, Any]:
        """Analyze PE sections"""
        if not self.pe:
            return {'sections': [], 'count': 0}
        
        try:
            sections = []
            for section in self.pe.sections:
                section_info = {
                    'name': section.Name.decode('utf-8', errors='replace').rstrip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': hex(section.Misc_VirtualSize),
                    'raw_address': hex(section.PointerToRawData),
                    'raw_size': hex(section.SizeOfRawData),
                    'characteristics': hex(section.Characteristics),
                    'characteristics_flags': self._get_section_characteristics(section.Characteristics),
                    'entropy': self._calculate_entropy(section.get_data()) if section.SizeOfRawData > 0 else 0
                }
                sections.append(section_info)
            
            return {
                'sections': sections,
                'count': len(sections)
            }
        except Exception as e:
            self.logger.error(f"Error analyzing sections: {e}", exc_info=True)
            return {'sections': [], 'count': 0}
    
    def _get_section_characteristics(self, characteristics: int) -> List[str]:
        """Get section characteristics flags"""
        flags = []
        for flag, name in SECTION_CHARACTERISTICS.items():
            if characteristics & flag:
                flags.append(name)
        return flags
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy efficiently (O(n) instead of O(n²))"""
        if not data:
            return 0.0
        
        try:
            # Count frequencies once - O(n)
            byte_counts = Counter(data)
            data_len = len(data)
            
            entropy = 0.0
            for count in byte_counts.values():
                p_x = count / data_len
                if p_x > 0:
                    entropy -= p_x * math.log2(p_x)
            
            return round(entropy, 4)
        except Exception as e:
            self.logger.warning(f"Error calculating entropy: {e}")
            return 0.0
    
    # ==================== RESOURCE EXTRACTION ====================
    
    def extract_resources(self) -> Dict[str, Any]:
        """Extract resources (version info, icons, strings, etc.)"""
        resources = {
            'version_info': {},
            'icons': [],
            'strings': [],
            'bitmaps': [],
            'dialogs': [],
            'menus': [],
            'cursors': [],
            'fonts': [],
            'rcdata': [],
            'version': [],
            'unknown': [],
            'resource_tree': {}
        }
        
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return resources
        
        try:
            # Extract version information
            resources['version_info'] = self._extract_version_info()
            
            # Build resource tree
            resources['resource_tree'] = self._build_resource_tree()
            
            # Extract other resources
            for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for resource_id in entry.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            resource_type = self._get_resource_type_name(entry.id)
                            # Ensure the resource type key exists
                            if resource_type not in resources:
                                resources[resource_type] = []
                            
                            try:
                                resources[resource_type].append({
                                    'id': resource_id.id if hasattr(resource_id, 'id') else None,
                                    'name': resource_id.name.string.decode('utf-8', errors='replace') if hasattr(resource_id, 'name') and resource_id.name else None,
                                    'language': resource_lang.id if hasattr(resource_lang, 'id') else None,
                                    'size': resource_lang.data.struct.Size,
                                    'offset': hex(resource_lang.data.struct.OffsetToData)
                                })
                            except Exception as e:
                                self.logger.warning(f"Error extracting resource: {e}")
        except Exception as e:
            self.logger.error(f"Error extracting resources: {e}", exc_info=True)
        
        return resources
    
    def _get_resource_type_name(self, resource_type: int) -> str:
        """Get resource type name"""
        return RESOURCE_TYPES.get(resource_type, 'unknown')
    
    def _extract_version_info(self) -> Dict[str, Any]:
        """Extract version information from resources"""
        version_info = {}
        
        def decode_value(value):
            """Decode bytes to string if needed"""
            if isinstance(value, bytes):
                try:
                    return value.decode('utf-8', errors='replace')
                except (UnicodeDecodeError, AttributeError):
                    try:
                        return value.decode('latin-1', errors='replace')
                    except (UnicodeDecodeError, AttributeError):
                        return f"<bytes: {len(value)} bytes>"
            return value
        
        try:
            if hasattr(self.pe, 'FileInfo'):
                for file_info in self.pe.FileInfo:
                    for entry in file_info:
                        try:
                            if hasattr(entry, 'StringTable'):
                                for st_entry in entry.StringTable:
                                    # Handle both dict and list cases
                                    if hasattr(st_entry, 'entries'):
                                        entries = st_entry.entries
                                        if isinstance(entries, dict):
                                            for key, value in entries.items():
                                                version_info[key] = decode_value(value)
                                        elif isinstance(entries, list):
                                            # If it's a list, iterate through it
                                            for item in entries:
                                                if isinstance(item, tuple) and len(item) == 2:
                                                    version_info[item[0]] = decode_value(item[1])
                        except (AttributeError, TypeError) as e:
                            self.logger.debug(f"Error processing StringTable: {e}")
                        
                        try:
                            if hasattr(entry, 'Var'):
                                var = entry.Var
                                # Handle both dict and list cases
                                if isinstance(var, dict):
                                    for key, value in var.items():
                                        version_info[key] = decode_value(value)
                                elif isinstance(var, list):
                                    for item in var:
                                        if isinstance(item, tuple) and len(item) == 2:
                                            version_info[item[0]] = decode_value(item[1])
                        except (AttributeError, TypeError) as e:
                            self.logger.debug(f"Error processing Var: {e}")
        except Exception as e:
            self.logger.warning(f"Error extracting version info: {e}")
        
        return version_info
    
    def _build_resource_tree(self) -> Dict[str, Any]:
        """Build resource tree structure"""
        tree = {}
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return tree
        
        try:
            for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                resource_type = self._get_resource_type_name(entry.id)
                tree[resource_type] = []
                
                if hasattr(entry, 'directory'):
                    for resource_id in entry.directory.entries:
                        resource_entry = {
                            'id': resource_id.id if hasattr(resource_id, 'id') else None,
                            'name': resource_id.name.string.decode('utf-8', errors='replace') if hasattr(resource_id, 'name') and resource_id.name else None
                        }
                        tree[resource_type].append(resource_entry)
        except Exception as e:
            self.logger.warning(f"Error building resource tree: {e}")
        
        return tree
    
    # ==================== DEPENDENCY MAPPING ====================
    
    def map_dependencies(self, recursive: bool = True, max_depth: int = 5) -> Dict[str, Any]:
        """Map DLL dependencies recursively with caching"""
        cache_key = (str(self.dll_path), recursive, max_depth)
        
        if self.enable_cache and cache_key in DLLSeeker._dependency_cache:
            self.logger.debug(f"Using cached dependencies for {self.dll_path}")
            return DLLSeeker._dependency_cache[cache_key]
        
        dependencies = {
            'direct': [],
            'all': set(),
            'tree': {},
            'missing': []
        }
        
        try:
            imports = self.analyze_imports()
            
            # Get direct dependencies
            for dll_name in imports.get('imports', {}).keys():
                dependencies['direct'].append(dll_name)
                dependencies['all'].add(dll_name)
                
                if recursive and max_depth > 0:
                    # Try to find and analyze dependency
                    dep_path = self._find_dll(dll_name)
                    if dep_path:
                        try:
                            with DLLSeeker(str(dep_path), enable_cache=self.enable_cache) as dep_seeker:
                                dep_data = dep_seeker.map_dependencies(recursive=True, max_depth=max_depth - 1)
                                dependencies['tree'][dll_name] = dep_data
                                dependencies['all'].update(dep_data['all'])
                        except Exception as e:
                            self.logger.warning(f"Error analyzing dependency {dll_name}: {e}")
                    else:
                        dependencies['missing'].append(dll_name)
            
            dependencies['all'] = list(dependencies['all'])
            
            if self.enable_cache:
                DLLSeeker._dependency_cache[cache_key] = dependencies
            
            return dependencies
        except Exception as e:
            self.logger.error(f"Error mapping dependencies: {e}", exc_info=True)
            return dependencies
    
    def _find_dll(self, dll_name: str) -> Optional[Path]:
        """Find DLL in common system paths"""
        search_paths = [
            Path(self.dll_path.parent),
            Path('C:/Windows/System32'),
            Path('C:/Windows/SysWOW64'),
            Path('C:/Windows'),
        ]
        
        # Add PATH environment variable
        if os.environ.get('PATH'):
            search_paths.extend([Path(p) for p in os.environ.get('PATH', '').split(os.pathsep) if p])
        
        for path in search_paths:
            try:
                full_path = path / dll_name
                if full_path.exists():
                    return full_path
            except (OSError, ValueError):
                continue
        
        return None
    
    # ==================== STRING EXTRACTION ====================
    
    def extract_strings(self, min_length: int = 4, encoding: Optional[str] = None) -> List[Dict[str, Any]]:
        """Extract readable strings from DLL with Unicode support"""
        strings = []
        
        if not self.pe:
            return strings
        
        encodings = [encoding] if encoding else ['utf-8', 'utf-16-le', 'utf-16-be', 'latin-1', 'ascii']
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ) as progress:
                task = progress.add_task("Extracting strings...", total=len(self.pe.sections))
                
                # Extract strings from all sections
                for section in self.pe.sections:
                    try:
                        data = section.get_data()
                        section_strings = self._extract_strings_from_data(data, min_length, encodings)
                        for s in section_strings:
                            strings.append({
                                'string': s['string'],
                                'section': section.Name.decode('utf-8', errors='replace').rstrip('\x00'),
                                'offset': hex(s['offset'] + section.VirtualAddress),
                                'length': s['length'],
                                'encoding': s.get('encoding', 'unknown')
                            })
                    except Exception as e:
                        self.logger.warning(f"Error extracting strings from section {section.Name}: {e}")
                    finally:
                        progress.update(task, advance=1)
        except Exception as e:
            self.logger.error(f"Error extracting strings: {e}", exc_info=True)
        
        return strings
    
    def _extract_strings_from_data(self, data: bytes, min_length: int, encodings: List[str]) -> List[Dict[str, Any]]:
        """Extract strings from binary data with multiple encoding support"""
        strings = []
        seen_strings = set()  # Avoid duplicates
        
        for encoding in encodings:
            try:
                if encoding in ['utf-16-le', 'utf-16-be']:
                    # Handle UTF-16 differently
                    decoded = data.decode(encoding, errors='ignore')
                    current_string = ''
                    start_offset = 0
                    
                    for i, char in enumerate(decoded):
                        if char.isprintable() and char not in '\x00':
                            if not current_string:
                                start_offset = i * 2  # UTF-16 uses 2 bytes per char
                            current_string += char
                        else:
                            if len(current_string) >= min_length and current_string not in seen_strings:
                                strings.append({
                                    'string': current_string,
                                    'offset': start_offset,
                                    'length': len(current_string.encode(encoding)),
                                    'encoding': encoding
                                })
                                seen_strings.add(current_string)
                            current_string = ''
                    
                    # Check for string at end
                    if len(current_string) >= min_length and current_string not in seen_strings:
                        strings.append({
                            'string': current_string,
                            'offset': start_offset,
                            'length': len(current_string.encode(encoding)),
                            'encoding': encoding
                        })
                        seen_strings.add(current_string)
                else:
                    # Handle single-byte encodings
                    current_string = b''
                    start_offset = 0
                    
                    for i, byte in enumerate(data):
                        if 32 <= byte <= 126 or (encoding != 'ascii' and byte > 127):
                            if not current_string:
                                start_offset = i
                            current_string += bytes([byte])
                        else:
                            if len(current_string) >= min_length:
                                try:
                                    decoded = current_string.decode(encoding, errors='ignore')
                                    if decoded.isprintable() and decoded not in seen_strings:
                                        strings.append({
                                            'string': decoded,
                                            'offset': start_offset,
                                            'length': len(current_string),
                                            'encoding': encoding
                                        })
                                        seen_strings.add(decoded)
                                except (UnicodeDecodeError, UnicodeError):
                                    pass
                            current_string = b''
                    
                    # Check for string at end
                    if len(current_string) >= min_length:
                        try:
                            decoded = current_string.decode(encoding, errors='ignore')
                            if decoded.isprintable() and decoded not in seen_strings:
                                strings.append({
                                    'string': decoded,
                                    'offset': start_offset,
                                    'length': len(current_string),
                                    'encoding': encoding
                                })
                                seen_strings.add(decoded)
                        except (UnicodeDecodeError, UnicodeError):
                            pass
            except (UnicodeDecodeError, UnicodeError, LookupError) as e:
                self.logger.debug(f"Error with encoding {encoding}: {e}")
                continue
        
        return strings
    
    # ==================== ADVANCED ANALYSIS ====================
    
    def analyze_tls_callbacks(self) -> List[str]:
        """Extract TLS (Thread Local Storage) callbacks"""
        if not self.pe:
            return []
        
        callbacks = []
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_TLS'):
                tls = self.pe.DIRECTORY_ENTRY_TLS.struct
                callback_array_rva = tls.AddressOfCallBacks
                
                if callback_array_rva:
                    # Parse callback array
                    # This is a simplified version - full implementation would need
                    # to resolve RVAs and parse the callback array properly
                    callbacks.append(hex(callback_array_rva))
        except Exception as e:
            self.logger.warning(f"Error analyzing TLS callbacks: {e}")
        
        return callbacks
    
    def analyze_exception_handlers(self) -> Dict[str, Any]:
        """Analyze exception handlers (SEH)"""
        if not self.pe:
            return {'handlers': [], 'count': 0}
        
        handlers = []
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXCEPTION'):
                for exc in self.pe.DIRECTORY_ENTRY_EXCEPTION:
                    handlers.append({
                        'start': hex(exc.struct.StartAddress),
                        'end': hex(exc.struct.EndAddress),
                        'handler': hex(exc.struct.HandlerAddress),
                        'unwind': hex(exc.struct.UnwindInfoAddress) if hasattr(exc.struct, 'UnwindInfoAddress') else None
                    })
        except Exception as e:
            self.logger.warning(f"Error analyzing exception handlers: {e}")
        
        return {'handlers': handlers, 'count': len(handlers)}
    
    def calculate_hashes(self) -> Dict[str, str]:
        """Calculate MD5, SHA1, SHA256 hashes"""
        hashes = {}
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        try:
            chunk_size = DEFAULT_CONFIG['chunk_size']
            with open(self.dll_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    for algo in hash_algorithms.values():
                        algo.update(chunk)
            
            for name, algo in hash_algorithms.items():
                hashes[name] = algo.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating hashes: {e}", exc_info=True)
        
        return hashes
    
    # ==================== ADVANCED ANALYSIS METHODS ====================
    
    @lru_cache(maxsize=1)
    def analyze_relocations(self) -> Dict[str, Any]:
        """Analyze relocations"""
        if not self.pe:
            return {'relocations': [], 'count': 0}
        
        try:
            analyzer = RelocationAnalyzer(self.pe)
            return analyzer.analyze()
        except Exception as e:
            self.logger.error(f"Error analyzing relocations: {e}", exc_info=True)
            return {'relocations': [], 'count': 0}
    
    @lru_cache(maxsize=1)
    def analyze_debug_info(self) -> Dict[str, Any]:
        """Extract debug information"""
        if not self.pe:
            return {'debug_info': [], 'count': 0}
        
        try:
            extractor = DebugExtractor(self.pe)
            return extractor.extract()
        except Exception as e:
            self.logger.error(f"Error extracting debug info: {e}", exc_info=True)
            return {'debug_info': [], 'count': 0}
    
    @lru_cache(maxsize=1)
    def analyze_certificates(self) -> Dict[str, Any]:
        """Analyze certificates"""
        if not self.pe:
            return {'signed': False, 'certificate_present': False}
        
        try:
            analyzer = CertificateAnalyzer(self.pe)
            return analyzer.analyze()
        except Exception as e:
            self.logger.error(f"Error analyzing certificates: {e}", exc_info=True)
            return {'signed': False, 'certificate_present': False}
    
    def categorize_strings(self, strings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Categorize extracted strings"""
        if strings is None:
            strings = self.extract_strings()
        
        try:
            return self.string_analyzer.analyze_strings(strings)
        except Exception as e:
            self.logger.error(f"Error categorizing strings: {e}", exc_info=True)
            return {'categorized_strings': [], 'statistics': {}}
    
    def detect_malware(self) -> Dict[str, Any]:
        """Perform malware detection analysis"""
        try:
            full_data = self._get_full_analysis()
            return self.malware_detector.analyze(full_data)
        except Exception as e:
            self.logger.error(f"Error in malware detection: {e}", exc_info=True)
            return {'risk_score': 0, 'risk_level': 'MINIMAL', 'indicators': []}
    
    def compare_with(self, other_dll_path: str) -> Dict[str, Any]:
        """Compare this DLL with another DLL"""
        try:
            from dll_seeker import DLLSeeker
            with DLLSeeker(other_dll_path, enable_cache=self.enable_cache) as other:
                other_data = other._get_full_analysis()
                this_data = self._get_full_analysis()
                
                comparator = DLLComparator(this_data, other_data)
                return comparator.compare()
        except Exception as e:
            self.logger.error(f"Error comparing DLLs: {e}", exc_info=True)
            return {'error': str(e)}
    
    def scan_with_yara(self, rules_path: str) -> List[Dict[str, Any]]:
        """Scan DLL with YARA rules"""
        if not YARA_AVAILABLE:
            self.logger.warning("YARA not available. Install with: pip install yara-python")
            return []
        
        try:
            scanner = YARAScanner()
            return scanner.scan_file(str(self.dll_path), rules_path)
        except Exception as e:
            self.logger.error(f"Error scanning with YARA: {e}", exc_info=True)
            return []
    
    def generate_dependency_graph(self, output_path: Optional[str] = None, format: str = 'dot') -> str:
        """Generate visual dependency graph"""
        try:
            deps = self.map_dependencies(recursive=True, max_depth=3)
            deps['main_dll'] = self.dll_path.name
            
            if format == 'html':
                output = output_path or f"{self.dll_path.stem}_dependencies.html"
                return self.graph_generator.generate_html_graph(deps, output)
            else:
                output = output_path or f"{self.dll_path.stem}_dependencies.dot"
                return self.graph_generator.generate_dot(deps, output)
        except Exception as e:
            self.logger.error(f"Error generating dependency graph: {e}", exc_info=True)
            return ""
    
    # ==================== SEARCH & FILTER ====================
    
    def search_exports(self, pattern: str, case_sensitive: bool = False) -> List[Dict[str, Any]]:
        """Search exports by pattern"""
        exports = self.analyze_exports()
        results = []
        
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            regex = re.compile(pattern, flags)
            
            for exp in exports.get('exports', []):
                if regex.search(exp['name']):
                    results.append(exp)
        except re.error as e:
            self.logger.error(f"Invalid regex pattern: {e}")
        
        return results
    
    def search_imports(self, pattern: str, case_sensitive: bool = False) -> List[Dict[str, Any]]:
        """Search imports by pattern"""
        imports = self.analyze_imports()
        results = []
        
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            regex = re.compile(pattern, flags)
            
            for dll_name, dll_data in imports.get('imports', {}).items():
                if regex.search(dll_name):
                    results.append({
                        'dll': dll_name,
                        'functions': dll_data['functions'],
                        'count': dll_data['count']
                    })
                else:
                    matching_funcs = [f for f in dll_data['functions'] if regex.search(f['name'])]
                    if matching_funcs:
                        results.append({
                            'dll': dll_name,
                            'functions': matching_funcs,
                            'count': len(matching_funcs)
                        })
        except re.error as e:
            self.logger.error(f"Invalid regex pattern: {e}")
        
        return results
    
    def search_strings(self, pattern: str, case_sensitive: bool = False) -> List[Dict[str, Any]]:
        """Search strings by pattern"""
        strings = self.extract_strings()
        results = []
        
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            regex = re.compile(pattern, flags)
            
            for s in strings:
                if regex.search(s['string']):
                    results.append(s)
        except re.error as e:
            self.logger.error(f"Invalid regex pattern: {e}")
        
        return results
    
    # ==================== METADATA ====================
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get comprehensive metadata about the DLL"""
        try:
            file_stat = self.dll_path.stat()
            
            headers = self.analyze_headers()
            
            metadata = {
                'file_path': str(self.dll_path),
                'file_name': self.dll_path.name,
                'file_size': file_stat.st_size,
                'file_size_mb': round(file_stat.st_size / (1024 * 1024), 2),
                'created': self._format_timestamp(file_stat.st_ctime),
                'modified': self._format_timestamp(file_stat.st_mtime),
                'accessed': self._format_timestamp(file_stat.st_atime),
                'is_valid_pe': True,
                'is_dll': 'DLL' in headers.get('coff_header', {}).get('characteristics_flags', []),
                'architecture': headers.get('optional_header', {}).get('architecture', 'Unknown'),
                'compiler_info': self._detect_compiler(),
                'digital_signature': self._check_digital_signature(),
                'hashes': self.calculate_hashes()
            }
            
            return metadata
        except Exception as e:
            self.logger.error(f"Error getting metadata: {e}", exc_info=True)
            return {}
    
    def _detect_compiler(self) -> Dict[str, Any]:
        """Try to detect compiler used"""
        compiler_info = {
            'detected': False,
            'compiler': 'Unknown',
            'version': None,
            'indicators': []
        }
        
        try:
            strings = self.extract_strings(min_length=3)
            string_text = ' '.join([s['string'] for s in strings[:100]])  # Check first 100 strings
            
            # Check for compiler indicators
            if 'Microsoft Visual C++' in string_text or 'MSVC' in string_text:
                compiler_info['detected'] = True
                compiler_info['compiler'] = 'Microsoft Visual C++'
                compiler_info['indicators'].append('MSVC strings found')
            
            if 'GCC' in string_text or 'GNU' in string_text:
                compiler_info['detected'] = True
                compiler_info['compiler'] = 'GCC'
                compiler_info['indicators'].append('GCC strings found')
            
            if 'MinGW' in string_text:
                compiler_info['detected'] = True
                compiler_info['compiler'] = 'MinGW'
                compiler_info['indicators'].append('MinGW strings found')
            
            # Check section names
            sections = self.analyze_sections()
            section_names = [s['name'] for s in sections.get('sections', [])]
            if '.debug' in ' '.join(section_names):
                compiler_info['indicators'].append('Debug sections present')
        except Exception as e:
            self.logger.warning(f"Error detecting compiler: {e}")
        
        return compiler_info
    
    def _check_digital_signature(self) -> Dict[str, Any]:
        """Check if DLL is digitally signed"""
        signature_info = {
            'signed': False,
            'certificate_present': False,
            'note': 'Full signature verification requires additional libraries'
        }
        
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
                signature_info['certificate_present'] = True
                signature_info['signed'] = True
        except Exception as e:
            self.logger.debug(f"Error checking digital signature: {e}")
        
        return signature_info
    
    # ==================== EXPORT TO FORMATS ====================
    
    def _get_full_analysis(self) -> Dict[str, Any]:
        """Get complete analysis data"""
        strings = self.extract_strings()[:self.config.get('max_string_length', 1000)]
        
        analysis = {
            'metadata': self.get_metadata(),
            'headers': self.analyze_headers(),
            'exports': self.analyze_exports(),
            'imports': self.analyze_imports(),
            'delay_imports': self.analyze_delay_imports(),
            'iat': self.analyze_iat(),
            'sections': self.analyze_sections(),
            'resources': self.extract_resources(),
            'dependencies': self.map_dependencies(recursive=False),
            'tls_callbacks': self.analyze_tls_callbacks(),
            'exception_handlers': self.analyze_exception_handlers(),
            'strings': strings,
            'relocations': self.analyze_relocations(),
            'debug_info': self.analyze_debug_info(),
            'certificates': self.analyze_certificates(),
        }
        
        # Add categorized strings if enabled
        if self.config.get('string_categorization', True):
            try:
                analysis['categorized_strings'] = self.categorize_strings(strings)
            except Exception as e:
                self.logger.warning(f"Error categorizing strings: {e}")
        
        # Add malware detection if enabled
        if self.config.get('malware_detection', True):
            try:
                analysis['malware_analysis'] = self.detect_malware()
            except Exception as e:
                self.logger.warning(f"Error in malware detection: {e}")
        
        # Add performance stats if profiling enabled
        if self.profiler.enabled:
            analysis['performance'] = self.profiler.get_statistics()
        
        return analysis
    
    def export_to_json(self, output_path: Optional[str] = None) -> str:
        """Export all analysis to JSON"""
        output_file = output_path or f"{self.dll_path.stem}_analysis.json"
        
        try:
            analysis = self._get_full_analysis()
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(analysis, f, indent=2, default=str)
            self.logger.info(f"Analysis exported to: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {e}", exc_info=True)
            raise
    
    def export_to_csv(self, output_path: Optional[str] = None, data_type: str = 'exports') -> str:
        """Export specific data to CSV"""
        output_file = output_path or f"{self.dll_path.stem}_{data_type}.csv"
        
        try:
            if data_type == 'exports':
                data = self.analyze_exports()
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=['name', 'ordinal', 'address', 'forwarded', 'forwarded_to'])
                    writer.writeheader()
                    for exp in data.get('exports', []):
                        writer.writerow(exp)
            
            elif data_type == 'imports':
                data = self.analyze_imports()
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['dll', 'function', 'ordinal', 'address', 'hint'])
                    for dll_name, dll_data in data.get('imports', {}).items():
                        for func in dll_data['functions']:
                            writer.writerow([
                                dll_name,
                                func['name'],
                                func['ordinal'] or '',
                                func['address'] or '',
                                func['hint'] or ''
                            ])
            
            elif data_type == 'sections':
                data = self.analyze_sections()
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        'name', 'virtual_address', 'virtual_size', 'raw_address', 
                        'raw_size', 'characteristics', 'entropy'
                    ])
                    writer.writeheader()
                    for section in data.get('sections', []):
                        writer.writerow({
                            'name': section['name'],
                            'virtual_address': section['virtual_address'],
                            'virtual_size': section['virtual_size'],
                            'raw_address': section['raw_address'],
                            'raw_size': section['raw_size'],
                            'characteristics': section['characteristics'],
                            'entropy': section['entropy']
                        })
            
            self.logger.info(f"CSV exported to: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Error exporting to CSV: {e}", exc_info=True)
            raise
    
    def export_to_markdown(self, output_path: Optional[str] = None) -> str:
        """Export analysis to Markdown"""
        output_file = output_path or f"{self.dll_path.stem}_analysis.md"
        
        try:
            analysis = self._get_full_analysis()
            md_content = self._format_as_markdown(analysis)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(md_content)
            
            self.logger.info(f"Markdown exported to: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Error exporting to Markdown: {e}", exc_info=True)
            raise
    
    def _format_as_markdown(self, analysis: Dict[str, Any]) -> str:
        """Format analysis data as Markdown"""
        md = f"# DLL Analysis Report: {self.dll_path.name}\n\n"
        md += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Metadata
        md += "## Metadata\n\n"
        metadata = analysis.get('metadata', {})
        for key, value in metadata.items():
            md += f"- **{key.replace('_', ' ').title()}**: {value}\n"
        md += "\n"
        
        # Exports
        exports = analysis.get('exports', {})
        md += f"## Exports ({exports.get('count', 0)})\n\n"
        for exp in exports.get('exports', [])[:20]:
            md += f"- `{exp['name']}` (Ordinal: {exp['ordinal']}, Address: {exp['address']})\n"
        if exports.get('count', 0) > 20:
            md += f"\n*... and {exports.get('count', 0) - 20} more exports*\n"
        md += "\n"
        
        # Imports
        imports = analysis.get('imports', {})
        md += f"## Imports ({imports.get('count', 0)} functions from {imports.get('dll_count', 0)} DLLs)\n\n"
        for dll_name, dll_data in list(imports.get('imports', {}).items())[:10]:
            md += f"### {dll_name}\n"
            for func in dll_data['functions'][:5]:
                md += f"- `{func['name']}`\n"
            if dll_data['count'] > 5:
                md += f"*... and {dll_data['count'] - 5} more functions*\n"
            md += "\n"
        md += "\n"
        
        return md
    
    def export_to_html(self, output_path: Optional[str] = None) -> str:
        """Export analysis to HTML"""
        output_file = output_path or f"{self.dll_path.stem}_analysis.html"
        
        try:
            analysis = self._get_full_analysis()
            html = self._format_as_html(analysis)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html)
            
            self.logger.info(f"HTML exported to: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Error exporting to HTML: {e}", exc_info=True)
            raise
    
    def _format_as_html(self, analysis: Dict[str, Any]) -> str:
        """Format analysis data as HTML"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>DLL Analysis: {self.dll_path.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ccc; padding-bottom: 5px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .metadata {{ background-color: #e7f3ff; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>DLL Analysis Report: {self.dll_path.name}</h1>
    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h2>Metadata</h2>
    <div class="metadata">
"""
        
        metadata = analysis.get('metadata', {})
        for key, value in metadata.items():
            html += f"        <p><strong>{key.replace('_', ' ').title()}:</strong> {value}</p>\n"
        
        html += """    </div>
    
    <h2>Exports</h2>
    <table>
        <tr>
            <th>Name</th>
            <th>Ordinal</th>
            <th>Address</th>
            <th>Forwarded</th>
        </tr>
"""
        
        exports = analysis.get('exports', {}).get('exports', [])[:50]
        for exp in exports:
            html += f"""        <tr>
            <td>{exp['name']}</td>
            <td>{exp['ordinal']}</td>
            <td>{exp['address']}</td>
            <td>{'Yes' if exp['forwarded'] else 'No'}</td>
        </tr>
"""
        
        html += """    </table>
</body>
</html>"""
        
        return html
    
    def export_to_xml(self, output_path: Optional[str] = None) -> str:
        """Export analysis to XML"""
        output_file = output_path or f"{self.dll_path.stem}_analysis.xml"
        
        try:
            analysis = self._get_full_analysis()
            xml_content = ExportFormats.export_to_xml(analysis, output_file)
            self.logger.info(f"XML exported to: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Error exporting to XML: {e}", exc_info=True)
            raise
    
    def export_to_yaml(self, output_path: Optional[str] = None) -> str:
        """Export analysis to YAML"""
        output_file = output_path or f"{self.dll_path.stem}_analysis.yaml"
        
        try:
            analysis = self._get_full_analysis()
            ExportFormats.export_to_yaml(analysis, output_file)
            self.logger.info(f"YAML exported to: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Error exporting to YAML: {e}", exc_info=True)
            raise
    
    def export_to_sql(self, output_path: Optional[str] = None) -> str:
        """Export analysis to SQL"""
        output_file = output_path or f"{self.dll_path.stem}_analysis.sql"
        
        try:
            analysis = self._get_full_analysis()
            ExportFormats.export_to_sql(analysis, output_file)
            self.logger.info(f"SQL exported to: {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Error exporting to SQL: {e}", exc_info=True)
            raise
    
    
    # ==================== DISPLAY METHODS ====================
    
    def display_full_analysis(self):
        """Display comprehensive analysis in console"""
        self.console.print(Panel.fit(
            f"[bold cyan]DLL Seeker - Full Analysis[/bold cyan]\n[bold]{self.dll_path.name}[/bold]",
            border_style="cyan"
        ))
        
        # Metadata
        metadata = self.get_metadata()
        self._display_metadata(metadata)
        
        # Headers
        headers = self.analyze_headers()
        self._display_headers(headers)
        
        # Exports
        exports = self.analyze_exports()
        self._display_exports(exports)
        
        # Imports
        imports = self.analyze_imports()
        self._display_imports(imports)
        
        # Delay imports
        delay_imports = self.analyze_delay_imports()
        if delay_imports.get('count', 0) > 0:
            self._display_delay_imports(delay_imports)
        
        # Sections
        sections = self.analyze_sections()
        self._display_sections(sections)
        
        # Resources
        resources = self.extract_resources()
        self._display_resources(resources)
        
        # Dependencies
        dependencies = self.map_dependencies(recursive=False)
        self._display_dependencies(dependencies)
        
        # Hashes
        hashes = self.calculate_hashes()
        if hashes:
            self._display_hashes(hashes)
    
    def _display_metadata(self, metadata: Dict[str, Any]):
        """Display metadata table"""
        table = Table(title="File Metadata", box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in metadata.items():
            if key != 'hashes':  # Hashes displayed separately
                table.add_row(key.replace('_', ' ').title(), str(value))
        
        self.console.print(table)
        self.console.print()
    
    def _display_hashes(self, hashes: Dict[str, str]):
        """Display file hashes"""
        table = Table(title="File Hashes", box=box.ROUNDED)
        table.add_column("Algorithm", style="cyan")
        table.add_column("Hash", style="green")
        
        for algo, hash_value in hashes.items():
            table.add_row(algo.upper(), hash_value)
        
        self.console.print(table)
        self.console.print()
    
    def _display_headers(self, headers: Dict[str, Any]):
        """Display headers information"""
        table = Table(title="PE Headers", box=box.ROUNDED)
        table.add_column("Header", style="cyan")
        table.add_column("Property", style="yellow")
        table.add_column("Value", style="green")
        
        opt_header = headers.get('optional_header', {})
        table.add_row("Architecture", "", opt_header.get('architecture', 'Unknown'))
        table.add_row("Entry Point", "", opt_header.get('entry_point', 'N/A'))
        table.add_row("Image Base", "", opt_header.get('image_base', 'N/A'))
        table.add_row("Subsystem", "", opt_header.get('subsystem_name', 'Unknown'))
        
        self.console.print(table)
        self.console.print()
    
    def _display_exports(self, exports: Dict[str, Any]):
        """Display exports table"""
        if exports.get('count', 0) == 0:
            self.console.print("[yellow]No exports found[/yellow]\n")
            return
        
        table = Table(title=f"Exports ({exports['count']})", box=box.ROUNDED)
        table.add_column("Name", style="cyan")
        table.add_column("Ordinal", style="yellow")
        table.add_column("Address", style="green")
        table.add_column("Forwarded", style="magenta")
        
        for exp in exports.get('exports', [])[:50]:  # Show first 50
            table.add_row(
                exp['name'],
                str(exp['ordinal']),
                exp['address'],
                "Yes" if exp['forwarded'] else "No"
            )
        
        if exports['count'] > 50:
            self.console.print(f"[dim]... and {exports['count'] - 50} more exports[/dim]")
        
        self.console.print(table)
        self.console.print()
    
    def _display_imports(self, imports: Dict[str, Any]):
        """Display imports tree"""
        if imports.get('count', 0) == 0:
            self.console.print("[yellow]No imports found[/yellow]\n")
            return
        
        tree = Tree(f"[cyan]Imports ({imports['dll_count']} DLLs, {imports['count']} functions)[/cyan]")
        
        for dll_name, dll_data in list(imports.get('imports', {}).items())[:20]:  # Show first 20 DLLs
            dll_branch = tree.add(f"[yellow]{dll_name}[/yellow] ({dll_data['count']} functions)")
            for func in dll_data['functions'][:10]:  # Show first 10 functions per DLL
                dll_branch.add(f"[green]{func['name']}[/green]")
            if dll_data['count'] > 10:
                dll_branch.add(f"[dim]... and {dll_data['count'] - 10} more[/dim]")
        
        if imports['dll_count'] > 20:
            tree.add(f"[dim]... and {imports['dll_count'] - 20} more DLLs[/dim]")
        
        self.console.print(tree)
        self.console.print()
    
    def _display_delay_imports(self, delay_imports: Dict[str, Any]):
        """Display delay-loaded imports"""
        if delay_imports.get('count', 0) == 0:
            return
        
        tree = Tree(f"[cyan]Delay-Loaded Imports ({delay_imports['count']} functions)[/cyan]")
        
        for entry in delay_imports.get('delay_imports', [])[:10]:
            dll_branch = tree.add(f"[yellow]{entry['dll']}[/yellow] ({entry['count']} functions)")
            for func in entry['functions'][:5]:
                dll_branch.add(f"[green]{func['name']}[/green]")
        
        self.console.print(tree)
        self.console.print()
    
    def _display_sections(self, sections: Dict[str, Any]):
        """Display sections table"""
        table = Table(title=f"Sections ({sections['count']})", box=box.ROUNDED)
        table.add_column("Name", style="cyan")
        table.add_column("Virtual Address", style="yellow")
        table.add_column("Virtual Size", style="green")
        table.add_column("Raw Size", style="magenta")
        table.add_column("Entropy", style="red")
        
        for section in sections.get('sections', []):
            table.add_row(
                section['name'],
                section['virtual_address'],
                section['virtual_size'],
                section['raw_size'],
                str(section['entropy'])
            )
        
        self.console.print(table)
        self.console.print()
    
    def _display_resources(self, resources: Dict[str, Any]):
        """Display resources"""
        if resources.get('version_info'):
            table = Table(title="Version Information", box=box.ROUNDED)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            
            def safe_str(obj):
                """Convert any object to a safe string representation"""
                if isinstance(obj, bytes):
                    try:
                        return obj.decode('utf-8', errors='replace')
                    except (UnicodeDecodeError, AttributeError):
                        try:
                            return obj.decode('latin-1', errors='replace')
                        except (UnicodeDecodeError, AttributeError):
                            return f"<bytes: {len(obj)} bytes>"
                elif isinstance(obj, (list, dict, tuple)):
                    return str(obj)
                elif obj is None:
                    return "N/A"
                else:
                    return str(obj)
            
            for key, value in resources['version_info'].items():
                safe_key = safe_str(key)
                safe_value = safe_str(value)
                table.add_row(safe_key, safe_value)
            
            self.console.print(table)
            self.console.print()
    
    def _display_dependencies(self, dependencies: Dict[str, Any]):
        """Display dependencies"""
        if not dependencies.get('direct'):
            self.console.print("[yellow]No dependencies found[/yellow]\n")
            return
        
        tree = Tree(f"[cyan]Dependencies ({len(dependencies['direct'])})[/cyan]")
        for dll in dependencies['direct']:
            tree.add(f"[yellow]{dll}[/yellow]")
        
        self.console.print(tree)
        self.console.print()


# ==================== BATCH PROCESSING ====================

def analyze_multiple(dll_paths: List[str], output_dir: Optional[str] = None, 
                    log_level: int = logging.INFO) -> Dict[str, Any]:
    """Analyze multiple DLLs"""
    results = {}
    output_path = Path(output_dir) if output_dir else None
    
    if output_path:
        output_path.mkdir(parents=True, exist_ok=True)
    
    for dll_path in dll_paths:
        try:
            with DLLSeeker(dll_path, log_level=log_level) as seeker:
                results[dll_path] = seeker._get_full_analysis()
                
                if output_path:
                    output_file = output_path / f"{seeker.dll_path.stem}_analysis.json"
                    seeker.export_to_json(str(output_file))
        except Exception as e:
            results[dll_path] = {'error': str(e)}
            logging.error(f"Error analyzing {dll_path}: {e}")
    
    return results


# ==================== MAIN ENTRY POINT ====================

def main():
    """Main entry point with argparse"""
    parser = argparse.ArgumentParser(
        description='DLL Seeker - Comprehensive DLL Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dll_seeker.py file.dll
  python dll_seeker.py file.dll --json output.json
  python dll_seeker.py file.dll --csv exports
  python dll_seeker.py file.dll --search "CreateFile"
  python dll_seeker.py file.dll --strings 6
  python dll_seeker.py file1.dll file2.dll --batch output_dir
        """
    )
    
    parser.add_argument('dll_paths', nargs='+', help='Path(s) to DLL file(s)')
    parser.add_argument('--json', nargs='?', const=True, metavar='OUTPUT',
                       help='Export to JSON (optional output path)')
    parser.add_argument('--csv', choices=['exports', 'imports', 'sections'],
                       help='Export to CSV')
    parser.add_argument('--html', nargs='?', const=True, metavar='OUTPUT',
                       help='Export to HTML (optional output path)')
    parser.add_argument('--markdown', nargs='?', const=True, metavar='OUTPUT',
                       help='Export to Markdown (optional output path)')
    parser.add_argument('--xml', nargs='?', const=True, metavar='OUTPUT',
                       help='Export to XML (optional output path)')
    parser.add_argument('--yaml', nargs='?', const=True, metavar='OUTPUT',
                       help='Export to YAML (optional output path)')
    parser.add_argument('--sql', nargs='?', const=True, metavar='OUTPUT',
                       help='Export to SQL (optional output path)')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--deps', action='store_true',
                       help='Show dependency tree')
    parser.add_argument('--graph', choices=['dot', 'html'], default='dot',
                       help='Generate dependency graph (dot or html)')
    parser.add_argument('--search', help='Search pattern (regex)')
    parser.add_argument('--strings', type=int, nargs='?', const=4, metavar='MIN_LEN',
                       help='Extract strings (min length, default: 4)')
    parser.add_argument('--categorize-strings', action='store_true',
                       help='Categorize extracted strings')
    parser.add_argument('--malware', action='store_true',
                       help='Perform malware detection analysis')
    parser.add_argument('--compare', metavar='OTHER_DLL',
                       help='Compare with another DLL file')
    parser.add_argument('--yara', metavar='RULES_FILE',
                       help='Scan with YARA rules')
    parser.add_argument('--profile', action='store_true',
                       help='Enable performance profiling')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress console output')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--batch', metavar='OUTPUT_DIR',
                       help='Batch process multiple DLLs to output directory')
    parser.add_argument('--no-cache', action='store_true',
                       help='Disable caching')
    parser.add_argument('--config', metavar='CONFIG_FILE',
                       help='Use configuration file')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO)
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Load configuration
    config = None
    if args.config:
        config = ConfigManager(args.config)
    if args.profile:
        if config is None:
            config = ConfigManager()
        config.set('enable_profiling', True)
    
    # Batch processing
    if args.batch or len(args.dll_paths) > 1:
        output_dir = args.batch if args.batch else None
        results = analyze_multiple(args.dll_paths, output_dir, log_level)
        if not args.quiet:
            print(f"\nProcessed {len(args.dll_paths)} DLL(s)")
            for path, result in results.items():
                if 'error' in result:
                    print(f"  {path}: ERROR - {result['error']}")
                else:
                    print(f"  {path}: OK")
        return
    
    # Single file processing
    dll_path = args.dll_paths[0]
    
    try:
        with DLLSeeker(dll_path, log_level=log_level, enable_cache=not args.no_cache, config=config) as seeker:
            # Enable profiling if requested
            if args.profile:
                seeker.profiler.enabled = True
            if args.json:
                output = args.output if args.output else (args.json if isinstance(args.json, str) else None)
                output_file = seeker.export_to_json(output)
                if not args.quiet:
                    print(f"Analysis exported to: {output_file}")
            
            elif args.csv:
                output_file = seeker.export_to_csv(args.output, data_type=args.csv)
                if not args.quiet:
                    print(f"CSV exported to: {output_file}")
            
            elif args.html:
                output = args.output if args.output else (args.html if isinstance(args.html, str) else None)
                output_file = seeker.export_to_html(output)
                if not args.quiet:
                    print(f"HTML exported to: {output_file}")
            
            elif args.markdown:
                output = args.output if args.output else (args.markdown if isinstance(args.markdown, str) else None)
                output_file = seeker.export_to_markdown(output)
                if not args.quiet:
                    print(f"Markdown exported to: {output_file}")
            
            elif args.xml:
                output = args.output if args.output else (args.xml if isinstance(args.xml, str) else None)
                output_file = seeker.export_to_xml(output)
                if not args.quiet:
                    print(f"XML exported to: {output_file}")
            
            elif args.yaml:
                output = args.output if args.output else (args.yaml if isinstance(args.yaml, str) else None)
                output_file = seeker.export_to_yaml(output)
                if not args.quiet:
                    print(f"YAML exported to: {output_file}")
            
            elif args.sql:
                output = args.output if args.output else (args.sql if isinstance(args.sql, str) else None)
                output_file = seeker.export_to_sql(output)
                if not args.quiet:
                    print(f"SQL exported to: {output_file}")
            
            elif args.compare:
                comparison = seeker.compare_with(args.compare)
                if not args.quiet:
                    summary = comparison.get('summary', {})
                    print(f"\nComparison Summary:")
                    print(f"  Similarity: {summary.get('similarity_score', 0):.1f}%")
                    print(f"  Total Differences: {summary.get('total_differences', 0)}")
                    print(f"  Identical: {summary.get('are_identical', False)}")
            
            elif args.malware:
                malware_analysis = seeker.detect_malware()
                if not args.quiet:
                    print(f"\nMalware Detection Results:")
                    print(f"  Risk Level: {malware_analysis.get('risk_level', 'UNKNOWN')}")
                    print(f"  Risk Score: {malware_analysis.get('risk_score', 0)}/100")
                    print(f"  Indicators: {len(malware_analysis.get('indicators', []))}")
                    for indicator in malware_analysis.get('indicators', [])[:10]:
                        print(f"    - {indicator}")
            
            elif args.yara:
                yara_results = seeker.scan_with_yara(args.yara)
                if not args.quiet:
                    if yara_results:
                        print(f"\nYARA Scan Results: {len(yara_results)} matches")
                        for match in yara_results:
                            print(f"  Rule: {match.get('rule', 'Unknown')}")
                            print(f"    Tags: {', '.join(match.get('tags', []))}")
                    else:
                        print("No YARA matches found")
            
            elif args.categorize_strings:
                strings = seeker.extract_strings()
                categorized = seeker.categorize_strings(strings)
                if not args.quiet:
                    print(f"\nString Categorization:")
                    print(f"  Total Strings: {categorized.get('total_strings', 0)}")
                    print(f"  Categorized: {categorized.get('categorized_count', 0)}")
                    print(f"  Categories Found: {', '.join(categorized.get('categories_found', []))}")
                    stats = categorized.get('statistics', {})
                    for cat, count in sorted(stats.items(), key=lambda x: x[1], reverse=True)[:10]:
                        print(f"    {cat}: {count}")
            
            elif args.deps:
                deps = seeker.map_dependencies(recursive=True)
                seeker._display_dependencies(deps)
            
            elif args.graph:
                output = args.output if args.output else None
                graph_file = seeker.generate_dependency_graph(output, format=args.graph)
                if not args.quiet:
                    print(f"Dependency graph generated: {graph_file}")
            
            elif args.search:
                if not args.quiet:
                    print(f"\nSearching for pattern: {args.search}\n")
                    print("Exports:")
                    for exp in seeker.search_exports(args.search):
                        print(f"  - {exp['name']}")
                    print("\nImports:")
                    for imp in seeker.search_imports(args.search):
                        print(f"  - {imp['dll']}: {len(imp['functions'])} functions")
                    print("\nStrings:")
                    for s in seeker.search_strings(args.search)[:20]:
                        print(f"  - {s['string'][:80]}")
            
            elif args.strings is not None:
                strings = seeker.extract_strings(min_length=args.strings)
                if not args.quiet:
                    print(f"\nFound {len(strings)} strings (min length: {args.strings})\n")
                    for s in strings[:100]:  # Show first 100
                        print(f"{s['offset']}: {s['string'][:80]}")
            
            else:
                seeker.display_full_analysis()
            
            # Show performance stats if profiling was enabled
            if args.profile and seeker.profiler.enabled:
                stats = seeker.profiler.get_statistics()
                if not args.quiet and stats.get('operations'):
                    print(f"\nPerformance Statistics:")
                    print(f"  Total Time: {stats.get('total_time', 0):.3f}s")
                    print(f"  Operations: {stats.get('operation_count', 0)}")
                    slowest = seeker.profiler.get_slowest_operations(5)
                    if slowest:
                        print(f"\n  Slowest Operations:")
                        for op in slowest:
                            print(f"    {op['name']}: {op['total_time']:.3f}s (avg: {op['average_time']:.3f}s)")
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 1
    except Exception as e:
        logging.error(f"Error: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
