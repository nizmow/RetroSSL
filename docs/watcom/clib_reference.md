# Open Watcom C Library Reference (Local Copy)

Source: https://open-watcom.github.io/open-watcom-v2-wikidocs/clib.html

## Overview

The Open Watcom C Library Reference provides a comprehensive overview of C library functions organized into several key categories:

## Key Function Categories:
- Character Manipulation
- Memory Manipulation  
- String Manipulation
- Conversion Functions
- Memory Allocation
- Math Functions
- Stream I/O
- Process Management
- Directory Operations

## Key Points

The library supports multiple memory models and provides functions for:
- Character and string handling
- Memory management
- Mathematical computations
- File and stream operations
- Process and thread creation
- System and environment interactions

**Important:** Library functions are called like program-defined functions, and the linker incorporates their code during compilation. Always include appropriate header files to enable compiler argument checking.

The reference is structured alphabetically and provides detailed descriptions of each function's purpose, usage, and potential variations across different programming scenarios.

## For SSL Development

When implementing SSL functionality, pay special attention to:
- Memory allocation functions for certificate handling
- String manipulation for parsing
- Stream I/O for network operations
- Conversion functions for data encoding

**Note:** For complete function details, refer to the full online documentation at the source URL above.