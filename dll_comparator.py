"""
DLL Comparator - Compare two DLL files
"""

from typing import Dict, List, Any, Optional, Set
from pathlib import Path


class DLLComparator:
    """Compare two DLL files and identify differences"""
    
    def __init__(self, dll1_data: Dict[str, Any], dll2_data: Dict[str, Any]):
        """Initialize comparator with two DLL analysis results"""
        self.dll1 = dll1_data
        self.dll2 = dll2_data
        self.differences = {}
    
    def compare(self) -> Dict[str, Any]:
        """Perform comprehensive comparison"""
        return {
            'metadata': self._compare_metadata(),
            'exports': self._compare_exports(),
            'imports': self._compare_imports(),
            'sections': self._compare_sections(),
            'resources': self._compare_resources(),
            'dependencies': self._compare_dependencies(),
            'summary': self._generate_summary()
        }
    
    def _compare_metadata(self) -> Dict[str, Any]:
        """Compare metadata"""
        meta1 = self.dll1.get('metadata', {})
        meta2 = self.dll2.get('metadata', {})
        
        differences = []
        same = []
        
        for key in set(list(meta1.keys()) + list(meta2.keys())):
            val1 = meta1.get(key)
            val2 = meta2.get(key)
            
            if val1 != val2:
                differences.append({
                    'field': key,
                    'dll1': val1,
                    'dll2': val2
                })
            else:
                same.append(key)
        
        return {
            'differences': differences,
            'same_fields': same,
            'difference_count': len(differences)
        }
    
    def _compare_exports(self) -> Dict[str, Any]:
        """Compare exports"""
        exp1 = {e['name']: e for e in self.dll1.get('exports', {}).get('exports', [])}
        exp2 = {e['name']: e for e in self.dll2.get('exports', {}).get('exports', [])}
        
        only_in_1 = set(exp1.keys()) - set(exp2.keys())
        only_in_2 = set(exp2.keys()) - set(exp1.keys())
        in_both = set(exp1.keys()) & set(exp2.keys())
        
        changed = []
        for name in in_both:
            if exp1[name] != exp2[name]:
                changed.append({
                    'name': name,
                    'dll1': exp1[name],
                    'dll2': exp2[name]
                })
        
        return {
            'only_in_dll1': list(only_in_1),
            'only_in_dll2': list(only_in_2),
            'in_both': list(in_both),
            'changed': changed,
            'dll1_count': len(exp1),
            'dll2_count': len(exp2),
            'difference_count': len(only_in_1) + len(only_in_2) + len(changed)
        }
    
    def _compare_imports(self) -> Dict[str, Any]:
        """Compare imports"""
        imp1 = self.dll1.get('imports', {}).get('imports', {})
        imp2 = self.dll2.get('imports', {}).get('imports', {})
        
        dlls1 = set(imp1.keys())
        dlls2 = set(imp2.keys())
        
        only_in_1 = dlls1 - dlls2
        only_in_2 = dlls2 - dlls1
        in_both = dlls1 & dlls2
        
        # Compare functions in common DLLs
        function_diffs = {}
        for dll in in_both:
            funcs1 = {f['name'] for f in imp1[dll].get('functions', [])}
            funcs2 = {f['name'] for f in imp2[dll].get('functions', [])}
            
            if funcs1 != funcs2:
                function_diffs[dll] = {
                    'only_in_dll1': list(funcs1 - funcs2),
                    'only_in_dll2': list(funcs2 - funcs1),
                    'in_both': list(funcs1 & funcs2)
                }
        
        return {
            'dlls_only_in_dll1': list(only_in_1),
            'dlls_only_in_dll2': list(only_in_2),
            'dlls_in_both': list(in_both),
            'function_differences': function_diffs,
            'dll1_dll_count': len(dlls1),
            'dll2_dll_count': len(dlls2),
            'difference_count': len(only_in_1) + len(only_in_2) + len(function_diffs)
        }
    
    def _compare_sections(self) -> Dict[str, Any]:
        """Compare sections"""
        sec1 = {s['name']: s for s in self.dll1.get('sections', {}).get('sections', [])}
        sec2 = {s['name']: s for s in self.dll2.get('sections', {}).get('sections', [])}
        
        only_in_1 = set(sec1.keys()) - set(sec2.keys())
        only_in_2 = set(sec2.keys()) - set(sec1.keys())
        in_both = set(sec1.keys()) & set(sec2.keys())
        
        changed = []
        for name in in_both:
            s1 = sec1[name]
            s2 = sec2[name]
            if s1.get('entropy') != s2.get('entropy') or \
               s1.get('virtual_size') != s2.get('virtual_size') or \
               s1.get('raw_size') != s2.get('raw_size'):
                changed.append({
                    'name': name,
                    'dll1': s1,
                    'dll2': s2
                })
        
        return {
            'only_in_dll1': list(only_in_1),
            'only_in_dll2': list(only_in_2),
            'in_both': list(in_both),
            'changed': changed,
            'difference_count': len(only_in_1) + len(only_in_2) + len(changed)
        }
    
    def _compare_resources(self) -> Dict[str, Any]:
        """Compare resources"""
        res1 = self.dll1.get('resources', {})
        res2 = self.dll2.get('resources', {})
        
        ver1 = res1.get('version_info', {})
        ver2 = res2.get('version_info', {})
        
        version_diffs = {}
        for key in set(list(ver1.keys()) + list(ver2.keys())):
            if ver1.get(key) != ver2.get(key):
                version_diffs[key] = {
                    'dll1': ver1.get(key),
                    'dll2': ver2.get(key)
                }
        
        return {
            'version_info_differences': version_diffs,
            'difference_count': len(version_diffs)
        }
    
    def _compare_dependencies(self) -> Dict[str, Any]:
        """Compare dependencies"""
        dep1 = set(self.dll1.get('dependencies', {}).get('direct', []))
        dep2 = set(self.dll2.get('dependencies', {}).get('direct', []))
        
        only_in_1 = dep1 - dep2
        only_in_2 = dep2 - dep1
        in_both = dep1 & dep2
        
        return {
            'only_in_dll1': list(only_in_1),
            'only_in_dll2': list(only_in_2),
            'in_both': list(in_both),
            'difference_count': len(only_in_1) + len(only_in_2)
        }
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate comparison summary"""
        export_diff = self._compare_exports()['difference_count']
        import_diff = self._compare_imports()['difference_count']
        section_diff = self._compare_sections()['difference_count']
        resource_diff = self._compare_resources()['difference_count']
        dep_diff = self._compare_dependencies()['difference_count']
        
        total_differences = export_diff + import_diff + section_diff + resource_diff + dep_diff
        
        return {
            'total_differences': total_differences,
            'export_differences': export_diff,
            'import_differences': import_diff,
            'section_differences': section_diff,
            'resource_differences': resource_diff,
            'dependency_differences': dep_diff,
            'are_identical': total_differences == 0,
            'similarity_score': self._calculate_similarity()
        }
    
    def _calculate_similarity(self) -> float:
        """Calculate similarity score (0-100)"""
        export_diff = self._compare_exports()['difference_count']
        import_diff = self._compare_imports()['difference_count']
        section_diff = self._compare_sections()['difference_count']
        
        exp1_count = self.dll1.get('exports', {}).get('count', 1)
        exp2_count = self.dll2.get('exports', {}).get('count', 1)
        max_exports = max(exp1_count, exp2_count, 1)
        
        imp1_count = self.dll1.get('imports', {}).get('dll_count', 1)
        imp2_count = self.dll2.get('imports', {}).get('dll_count', 1)
        max_imports = max(imp1_count, imp2_count, 1)
        
        sec1_count = self.dll1.get('sections', {}).get('count', 1)
        sec2_count = self.dll2.get('sections', {}).get('count', 1)
        max_sections = max(sec1_count, sec2_count, 1)
        
        export_similarity = (1 - export_diff / max_exports) * 100
        import_similarity = (1 - import_diff / max_imports) * 100
        section_similarity = (1 - section_diff / max_sections) * 100
        
        # Weighted average
        similarity = (export_similarity * 0.4 + import_similarity * 0.4 + section_similarity * 0.2)
        
        return max(0, min(100, similarity))

