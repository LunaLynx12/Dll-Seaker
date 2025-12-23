"""
Setup script for DLL Seeker
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="dll-seeker",
    version="1.0.0",
    description="Comprehensive DLL analysis tool for Windows",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="DLL Seeker Contributors",
    author_email="",
    url="https://github.com/yourusername/dll-seeker",
    packages=find_packages(exclude=["tests", "venv", "__pycache__"]),
    py_modules=[
        "dll_seeker",
        "constants",
        "string_analyzer",
        "malware_detector",
        "dll_comparator",
        "graph_generator",
        "performance_profiler",
        "relocation_analyzer",
        "debug_extractor",
        "certificate_analyzer",
        "yara_scanner",
        "config_manager",
        "export_formats",
    ],
    install_requires=requirements,
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "dll-seeker=dll_seeker:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: Microsoft :: Windows",
    ],
    keywords="dll pe analysis security malware reverse-engineering",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/dll-seeker/issues",
        "Source": "https://github.com/yourusername/dll-seeker",
        "Documentation": "https://github.com/yourusername/dll-seeker#readme",
    },
)

