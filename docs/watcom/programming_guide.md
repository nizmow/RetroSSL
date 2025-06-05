# Open Watcom C/C++ Programmer's Guide (Local Copy)

Source: https://open-watcom.github.io/open-watcom-v2-wikidocs/cpguide.html

## Overview

The Open Watcom C/C++ Programmer's Guide covers application development for multiple environments.

## Supported Target Environments:
- 16-bit and 32-bit DOS
- **Windows 3.x**
- OS/2  
- **Windows NT** ← Our primary target (Win98 compatible)
- Novell NetWare

## Key Features Covered:
- Detailed instructions for compiling and debugging applications
- Sample code for different platforms
- Guidance on memory management
- Interrupt handling techniques
- Mixed language programming

## Important for Our Project: DOS/4GW

The guide explains DOS/4GW, which is relevant for understanding the environment:

> "DOS/4GW is a subset of Tenberry Software's DOS/4G product"

**Restrictions:**
- Only executes programs built with Open Watcom compilers
- Limited to 32MB of memory
- No TSR or advanced VMM capabilities

## Practical Code Examples

The guide provides practical examples for:
- Writing to video memory
- Accessing system interrupts  
- Managing memory in extended DOS environments

## Memory Management

Critical for SSL implementation - the guide covers:
- Different memory models
- Dynamic allocation strategies
- Memory protection in different environments

## For SSL Development

Key sections to reference:
- Memory management (for certificate storage)
- Interrupt handling (for network operations)
- Mixed language programming (if integrating assembly)
- Platform-specific compilation flags

## Cross-Platform Development

The guide emphasizes techniques for writing portable code across:
- Different Windows versions
- Various memory models
- Multiple target architectures

**Note:** For complete details on compilation flags, memory models, and platform-specific techniques, refer to the full online documentation.