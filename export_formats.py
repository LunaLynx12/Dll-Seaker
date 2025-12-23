"""
Export Formats - Additional export formats (XML, YAML)
"""

import json
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class ExportFormats:
    """Handle additional export formats"""
    
    @staticmethod
    def export_to_xml(data: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Export data to XML format"""
        root = ET.Element('DLLAnalysis')
        root.set('timestamp', datetime.now().isoformat())
        
        def dict_to_xml(parent, d):
            for key, value in d.items():
                if isinstance(value, dict):
                    elem = ET.SubElement(parent, key)
                    dict_to_xml(elem, value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            elem = ET.SubElement(parent, key)
                            dict_to_xml(elem, item)
                        else:
                            elem = ET.SubElement(parent, key)
                            elem.text = str(item)
                else:
                    elem = ET.SubElement(parent, key)
                    elem.text = str(value)
        
        dict_to_xml(root, data)
        
        xml_str = ET.tostring(root, encoding='unicode')
        # Pretty print
        from xml.dom import minidom
        dom = minidom.parseString(xml_str)
        pretty_xml = dom.toprettyxml(indent='  ')
        
        if output_path:
            Path(output_path).write_text(pretty_xml, encoding='utf-8')
        
        return pretty_xml
    
    @staticmethod
    def export_to_yaml(data: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Export data to YAML format"""
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML not installed. Install with: pip install pyyaml")
        
        yaml_str = yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)
        
        if output_path:
            Path(output_path).write_text(yaml_str, encoding='utf-8')
        
        return yaml_str
    
    @staticmethod
    def export_to_sql(data: Dict[str, Any], output_path: Optional[str] = None, table_name: str = 'dll_analysis') -> str:
        """Export data to SQL INSERT statements"""
        sql_lines = [
            f"-- DLL Analysis Export",
            f"-- Generated: {datetime.now().isoformat()}",
            f"",
            f"CREATE TABLE IF NOT EXISTS {table_name} (",
            f"  id INTEGER PRIMARY KEY AUTOINCREMENT,",
            f"  analysis_data TEXT,",
            f"  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            f");",
            f"",
        ]
        
        # Convert data to JSON for storage
        json_data = json.dumps(data, default=str)
        # Escape single quotes for SQL
        json_data_escaped = json_data.replace("'", "''")
        
        sql_lines.append(f"INSERT INTO {table_name} (analysis_data) VALUES ('{json_data_escaped}');")
        
        sql_content = '\n'.join(sql_lines)
        
        if output_path:
            Path(output_path).write_text(sql_content, encoding='utf-8')
        
        return sql_content

