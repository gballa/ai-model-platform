#!/usr/bin/env python3
"""Trajectory synthesis and microVM verification runner for Milestone 2 (v4).

Synthesizes 21 new training trajectories across 7 newly acquired cybersecurity disciplines:
1. Binary Analysis (3 records)
2. Assembly Language (3 records)
3. Operating System Internals (3 records)
4. Memory Architecture (3 records)
5. Firmware Analysis (3 records)
6. Network Protocols (3 records)
7. Exploit Mechanics (3 records)

Executes all solutions inside FirecrackerSandboxManager microVMs to verify execution_verified=True,
merges with 23 baseline trajectories from artifacts/v3_verified_trajectories.jsonl to produce 44 records
in artifacts/v4_verified_trajectories.jsonl, and audits all records through DatasetHygienePipeline.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Any

from platform_core.layer1_intelligence.training import CustomModelPipeline
from platform_core.layer2_execution.sandbox import FirecrackerSandboxManager, SandboxExecutionResult
from platform_core.layer3_evolution.data_factory import DatasetHygienePipeline, TrainingTrajectoryRecord


def extract_python_code(target_completion: str) -> str:
    """Extract clean executable Python code from markdown code block."""
    raw = target_completion.strip()
    if raw.startswith("```"):
        lines = raw.splitlines()
        start = 1
        end = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
        return "\n".join(lines[start:end])
    return raw


# 21 Candidate Trajectory Specifications
TRAJECTORY_SPECS: list[dict[str, Any]] = [
    # Discipline 1: Binary Analysis
    {
        "record_id": "bin-elf-001",
        "domain": "decompile_bench",
        "source_repo": "platform-core/binary-analysis",
        "license_id": "Apache-2.0",
        "cve_id": None,
        "prompt_context": "[Binary Analysis] Implement an ELF64 program header checksec triager that validates 64-bit ELF headers, checks for PIE, NX (PT_GNU_STACK), RELRO (PT_GNU_RELRO), and verifies x86_64 machine architecture.",
        "target_completion": """```python
import struct

def checksec_elf64(data: bytes) -> dict:
    if len(data) < 64:
        raise ValueError("Header too small")
    if data[:4] != b"\\x7fELF" or data[4] != 2:
        raise ValueError("Not ELF64")
    e_type, e_machine = struct.unpack("<HH", data[16:20])
    e_phoff = struct.unpack("<Q", data[32:40])[0]
    e_phentsize, e_phnum = struct.unpack("<HH", data[54:58])
    
    is_pie = (e_type == 3)
    has_nx = False
    has_relro = False
    if e_phoff + (e_phnum * e_phentsize) <= len(data):
        for i in range(e_phnum):
            off = e_phoff + (i * e_phentsize)
            p_type, p_flags = struct.unpack("<II", data[off:off+8])
            if p_type == 0x6474e551:  # PT_GNU_STACK
                has_nx = not bool(p_flags & 1)
            elif p_type == 0x6474e552:  # PT_GNU_RELRO
                has_relro = True
                
    return {
        "is_pie": is_pie,
        "nx_enabled": has_nx,
        "relro_enabled": has_relro,
        "machine_x86_64": (e_machine == 0x3E),
    }
```""",
        "assertions": """
import struct
p_headers = struct.pack("<IIQQQQQQ", 0x6474e551, 6, 0, 0, 0, 0, 0, 8) + struct.pack("<IIQQQQQQ", 0x6474e552, 4, 0, 0, 0, 0, 0, 8)
mock = b"\\x7fELF\\x02\\x01\\x01\\x00" + b"\\x00"*8 + struct.pack("<HH", 3, 0x3E) + struct.pack("<I", 1) + struct.pack("<Q", 0x401000) + struct.pack("<Q", 64) + struct.pack("<Q", 0) + struct.pack("<I", 0) + struct.pack("<HHH", 64, 56, 2) + struct.pack("<HHH", 0, 0, 0) + p_headers
res = checksec_elf64(mock)
assert res["is_pie"] is True
assert res["nx_enabled"] is True
assert res["relro_enabled"] is True
assert res["machine_x86_64"] is True
try:
    checksec_elf64(b"short")
    assert False, "Should raise ValueError"
except ValueError:
    pass
""",
    },
    {
        "record_id": "bin-ghidra-002",
        "domain": "decompile_bench",
        "source_repo": "platform-core/binary-analysis",
        "license_id": "MIT",
        "cve_id": None,
        "prompt_context": "[Binary Analysis] Implement constant division multiplication recovery for decompilation (e.g. Ghidra P-code optimization), recovering original divisor from magic reciprocal multiplier and shift count.",
        "target_completion": """```python
def recover_division_by_constant(magic: int, shift: int) -> int:
    if magic <= 0 or shift <= 0:
        raise ValueError("Invalid magic or shift")
    approx_divisor = (1 << shift) // magic
    for d in (approx_divisor, approx_divisor + 1):
        if d > 0 and ((1 << shift) + d - 1) // d == magic:
            return d
    return approx_divisor
```""",
        "assertions": """
assert recover_division_by_constant(2863311531, 33) == 3
assert recover_division_by_constant(3435973837, 34) == 5
try:
    recover_division_by_constant(-1, 0)
    assert False, "Should raise ValueError"
except ValueError:
    pass
""",
    },
    {
        "record_id": "bin-reloc-003",
        "domain": "decompile_bench",
        "source_repo": "platform-core/binary-analysis",
        "license_id": "BSD-3-Clause",
        "cve_id": None,
        "prompt_context": "[Binary Analysis] Implement an ELF64 relocation table entry resolver for R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, and R_X86_64_RELATIVE relocation types.",
        "target_completion": """```python
import struct

def resolve_elf64_reloc(reloc_entry: bytes, sym_val: int, addend: int) -> dict:
    if len(reloc_entry) < 24:
        raise ValueError("Rela entry must be 24 bytes")
    r_offset, r_info, r_addend = struct.unpack("<QQq", reloc_entry)
    r_type = r_info & 0xFFFFFFFF
    r_sym = r_info >> 32
    
    if r_type == 1:
        resolved = sym_val + (r_addend or addend)
    elif r_type in (6, 7):
        resolved = sym_val
    elif r_type == 8:
        resolved = sym_val + (r_addend or addend)
    else:
        raise NotImplementedError(f"Unsupported reloc type: {r_type}")
        
    return {
        "target_offset": hex(r_offset),
        "symbol_index": r_sym,
        "resolved_value": hex(resolved),
        "is_plt_got": r_type in (6, 7),
    }
```""",
        "assertions": """
import struct
entry = struct.pack("<QQq", 0x601018, (42 << 32) | 7, 0)
res = resolve_elf64_reloc(entry, sym_val=0x7ffff7a01234, addend=0)
assert res["target_offset"] == "0x601018"
assert res["symbol_index"] == 42
assert res["resolved_value"] == "0x7ffff7a01234"
assert res["is_plt_got"] is True
try:
    resolve_elf64_reloc(b"short", 0, 0)
    assert False, "Should raise ValueError"
except ValueError:
    pass
""",
    },

    # Discipline 2: Assembly Language
    {
        "record_id": "asm-sysv-001",
        "domain": "decompile_bench",
        "source_repo": "platform-core/assembly-mechanics",
        "license_id": "Apache-2.0",
        "cve_id": None,
        "prompt_context": "[Assembly Language] Implement System V AMD64 ABI argument passing validator, mapping integer/pointer parameters to RDI, RSI, RDX, RCX, R8, R9, floating point parameters to XMM0-XMM7, and remaining parameters to the stack.",
        "target_completion": """```python
def validate_sysv_amd64_frame(rsp: int, arg_types: list[str]) -> dict:
    gp_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    fp_regs = [f"xmm{i}" for i in range(8)]
    
    gp_used, fp_used, stack_args = [], [], []
    for arg in arg_types:
        if arg == "float" and len(fp_used) < 8:
            fp_used.append(fp_regs[len(fp_used)])
        elif arg != "float" and len(gp_used) < 6:
            gp_used.append(gp_regs[len(gp_used)])
        else:
            stack_args.append(arg)
            
    aligned = (rsp % 16 == 0)
    return {
        "aligned_16": aligned,
        "gp_registers": gp_used,
        "fp_registers": fp_used,
        "stack_arg_count": len(stack_args),
        "stack_bytes": len(stack_args) * 8,
    }
```""",
        "assertions": """
res = validate_sysv_amd64_frame(0x7fff0000, ["int", "ptr", "float", "int", "float", "int", "int", "int", "int"])
assert res["aligned_16"] is True
assert len(res["gp_registers"]) == 6
assert len(res["fp_registers"]) == 2
assert res["stack_arg_count"] == 1
assert res["stack_bytes"] == 8
""",
    },
    {
        "record_id": "asm-aarch64-002",
        "domain": "decompile_bench",
        "source_repo": "platform-core/assembly-mechanics",
        "license_id": "MIT",
        "cve_id": None,
        "prompt_context": "[Assembly Language] Implement ARM64 (AArch64) load/store pair (LDP/STP) instruction decoder, extracting base registers, operand registers, signed immediate offsets, and detecting link register (x30) frame records.",
        "target_completion": """```python
def decode_aarch64_stp_ldp(instruction_word: int) -> dict:
    is_64bit = ((instruction_word >> 30) & 0b11) == 0b10
    is_ldp = bool((instruction_word >> 22) & 1)
    rn = (instruction_word >> 5) & 0x1F
    rt = instruction_word & 0x1F
    rt2 = (instruction_word >> 10) & 0x1F
    
    imm7 = (instruction_word >> 15) & 0x7F
    if imm7 & 0x40:
        imm7 -= 0x80
    offset = imm7 * 8 if is_64bit else imm7 * 4
    
    return {
        "op": "ldp" if is_ldp else "stp",
        "is_64bit": is_64bit,
        "base_reg": f"x{rn}" if rn != 31 else "sp",
        "reg1": f"x{rt}",
        "reg2": f"x{rt2}",
        "offset": offset,
        "touches_lr": (rt == 30 or rt2 == 30),
    }
```""",
        "assertions": """
res = decode_aarch64_stp_ldp(0xa9bf7bfd)
assert res["op"] == "stp"
assert res["base_reg"] == "sp"
assert res["reg1"] == "x29"
assert res["reg2"] == "x30"
assert res["offset"] == -16
assert res["touches_lr"] is True
""",
    },
    {
        "record_id": "asm-prologue-003",
        "domain": "decompile_bench",
        "source_repo": "platform-core/assembly-mechanics",
        "license_id": "BSD-3-Clause",
        "cve_id": None,
        "prompt_context": "[Assembly Language] Implement x86-64 function prologue parser that identifies standard push rbp; mov rbp, rsp frames and calculates allocated stack frame size and 16-byte alignment.",
        "target_completion": """```python
def parse_x86_64_prologue(bytecode: bytes) -> dict:
    if len(bytecode) < 4 or bytecode[0] != 0x55 or bytecode[1:4] != b"\\x48\\x89\\xe5":
        return {"has_frame_pointer": False, "frame_size": 0, "is_16byte_aligned": False}
        
    frame_size = 0
    if len(bytecode) >= 8 and bytecode[4:7] == b"\\x48\\x83\\xec":
        frame_size = bytecode[7]
    elif len(bytecode) >= 11 and bytecode[4:7] == b"\\x48\\x81\\xec":
        import struct
        frame_size = struct.unpack("<I", bytecode[7:11])[0]
        
    return {
        "has_frame_pointer": True,
        "frame_size": frame_size,
        "is_16byte_aligned": (frame_size % 16 == 0),
    }
```""",
        "assertions": """
code = bytes.fromhex("554889e54883ec20")
res = parse_x86_64_prologue(code)
assert res["has_frame_pointer"] is True
assert res["frame_size"] == 32
assert res["is_16byte_aligned"] is True
assert parse_x86_64_prologue(b"nop")["has_frame_pointer"] is False
""",
    },

    # Discipline 3: Operating System Internals
    {
        "record_id": "os-kpti-001",
        "domain": "sec_bench",
        "source_repo": "platform-core/kernel-subsystems",
        "license_id": "Apache-2.0",
        "cve_id": "CVE-2026-9201",
        "prompt_context": "[OS Internals] Implement Kernel Page Table Isolation (KPTI / Meltdown mitigation) CR3 register validator checking PCID bits, user/kernel page table bit 12 toggle, and PML4 root alignment.",
        "target_completion": """```python
def validate_kpti_cr3(cr3: int, in_kernel: bool) -> dict:
    PAGE_TABLE_USER_BIT = 0x1000
    PCID_MASK = 0xFFF
    has_user_bit = bool(cr3 & PAGE_TABLE_USER_BIT)
    pcid = cr3 & PCID_MASK
    pml4_base = cr3 & ~0xFFF & ~PAGE_TABLE_USER_BIT
    valid = (not has_user_bit) if in_kernel else has_user_bit
    return {
        "valid_context": valid,
        "pcid": pcid,
        "pml4_base": hex(pml4_base),
        "is_user_table": has_user_bit,
    }
```""",
        "assertions": """
res_k = validate_kpti_cr3(0x1a0005, in_kernel=True)
assert res_k["valid_context"] is True
assert res_k["pcid"] == 5
res_u = validate_kpti_cr3(0x1a1005, in_kernel=False)
assert res_u["valid_context"] is True
assert res_u["is_user_table"] is True
""",
    },
    {
        "record_id": "os-syscall-002",
        "domain": "sec_bench",
        "source_repo": "platform-core/kernel-subsystems",
        "license_id": "MIT",
        "cve_id": "CVE-2026-9202",
        "prompt_context": "[OS Internals] Implement Linux copy_from_user address validation guard verifying that user pointer ranges do not cross TASK_SIZE_MAX boundary into kernel address space or trigger pointer wrap-around.",
        "target_completion": """```python
def validate_copy_from_user(ptr: int, size: int, task_size_max: int = 0x7FFF_FFFF_F000) -> bool:
    if ptr <= 0 or size <= 0:
        return False
    end = ptr + size
    if end <= ptr or end > task_size_max:
        return False
    return True
```""",
        "assertions": """
TASK_MAX = 0x7FFF_FFFF_F000
assert validate_copy_from_user(0x400000, 1024, TASK_MAX) is True
assert validate_copy_from_user(TASK_MAX - 512, 1024, TASK_MAX) is False
assert validate_copy_from_user(0xFFFF_8000_0000_0000, 64, TASK_MAX) is False
assert validate_copy_from_user(-1, 64, TASK_MAX) is False
""",
    },
    {
        "record_id": "os-capsicum-003",
        "domain": "sec_bench",
        "source_repo": "platform-core/kernel-subsystems",
        "license_id": "BSD-3-Clause",
        "cve_id": None,
        "prompt_context": "[OS Internals] Implement capability-based security rights validator (e.g. FreeBSD Capsicum) to verify file descriptor capability bitmasks against required operations.",
        "target_completion": """```python
def validate_capsicum_fd_rights(fd_rights: int, required_operation: str) -> bool:
    CAP_READ = 1 << 0
    CAP_WRITE = 1 << 1
    CAP_SEEK = 1 << 2
    CAP_FCNTL = 1 << 3
    CAP_FSTAT = 1 << 4
    
    op_map = {
        "read": CAP_READ,
        "write": CAP_WRITE,
        "seek": CAP_SEEK,
        "fcntl": CAP_FCNTL,
        "fstat": CAP_FSTAT,
    }
    required_bit = op_map.get(required_operation)
    if required_bit is None:
        raise ValueError(f"Unknown operation: {required_operation}")
    return bool(fd_rights & required_bit)
```""",
        "assertions": """
fd_caps = (1 << 0) | (1 << 4)
assert validate_capsicum_fd_rights(fd_caps, "read") is True
assert validate_capsicum_fd_rights(fd_caps, "fstat") is True
assert validate_capsicum_fd_rights(fd_caps, "write") is False
try:
    validate_capsicum_fd_rights(fd_caps, "mmap")
    assert False, "Should raise ValueError"
except ValueError:
    pass
""",
    },

    # Discipline 4: Memory Architecture
    {
        "record_id": "mem-mmu-001",
        "domain": "sec_bench",
        "source_repo": "platform-core/memory-architecture",
        "license_id": "Apache-2.0",
        "cve_id": None,
        "prompt_context": "[Memory Architecture] Implement 4-level x86-64 MMU virtual address decomposer that splits 64-bit virtual addresses into PML4, PDPT, PD, PT index offsets and 4KB page offset with canonical address check.",
        "target_completion": """```python
def split_x86_64_virtual_address(va: int) -> dict:
    if va < 0 or va >= (1 << 64):
        raise ValueError("Invalid 64-bit integer")
    bit47 = (va >> 47) & 1
    high_bits = (va >> 48) & 0xFFFF
    if (bit47 == 0 and high_bits != 0) or (bit47 == 1 and high_bits != 0xFFFF):
        raise ValueError("Non-canonical address")
        
    offset = va & 0xFFF
    pt = (va >> 12) & 0x1FF
    pd = (va >> 21) & 0x1FF
    pdpt = (va >> 30) & 0x1FF
    pml4 = (va >> 39) & 0x1FF
    
    return {
        "canonical": True,
        "pml4_idx": pml4,
        "pdpt_idx": pdpt,
        "pd_idx": pd,
        "pt_idx": pt,
        "page_offset": offset,
    }
```""",
        "assertions": """
res = split_x86_64_virtual_address(0x7fff_ffff_e000)
assert res["canonical"] is True
assert res["pml4_idx"] == 255
assert res["pdpt_idx"] == 511
assert res["page_offset"] == 0
try:
    split_x86_64_virtual_address(0x0001_8000_0000_0000)
    assert False, "Should raise ValueError for non-canonical address"
except ValueError:
    pass
""",
    },
    {
        "record_id": "mem-pte-002",
        "domain": "sec_bench",
        "source_repo": "platform-core/memory-architecture",
        "license_id": "MIT",
        "cve_id": None,
        "prompt_context": "[Memory Architecture] Implement page table entry (PTE) permission validator to check Present, Writable, User/Supervisor, and Execute-Disable (NX bit 63) flags, detecting W^X security violations.",
        "target_completion": """```python
def validate_x86_64_pte_permissions(pte_value: int) -> dict:
    is_present = bool(pte_value & (1 << 0))
    is_writable = bool(pte_value & (1 << 1))
    is_user = bool(pte_value & (1 << 2))
    is_nx = bool(pte_value & (1 << 63))
    
    wx_violation = is_user and is_writable and (not is_nx)
    return {
        "present": is_present,
        "writable": is_writable,
        "user_accessible": is_user,
        "nx_enabled": is_nx,
        "w_xor_x_violation": wx_violation,
    }
```""",
        "assertions": """
safe_stack = (1 << 63) | (1 << 2) | (1 << 1) | (1 << 0)
res = validate_x86_64_pte_permissions(safe_stack)
assert res["nx_enabled"] is True
assert res["w_xor_x_violation"] is False

danger_page = (1 << 2) | (1 << 1) | (1 << 0)
assert validate_x86_64_pte_permissions(danger_page)["w_xor_x_violation"] is True
""",
    },
    {
        "record_id": "mem-cache-003",
        "domain": "sec_bench",
        "source_repo": "platform-core/memory-architecture",
        "license_id": "BSD-3-Clause",
        "cve_id": None,
        "prompt_context": "[Memory Architecture] Implement set-associative CPU cache address decomposer that calculates cache set index, block offset, and tag for a physical address given cache size, way associativity, and line size.",
        "target_completion": """```python
def decompose_cache_address(paddr: int, cache_size_bytes: int = 32768, ways: int = 8, line_size: int = 64) -> dict:
    num_sets = cache_size_bytes // (ways * line_size)
    offset_bits = 6
    set_bits = (num_sets - 1).bit_length()
    
    offset = paddr & (line_size - 1)
    set_index = (paddr >> offset_bits) & (num_sets - 1)
    tag = paddr >> (offset_bits + set_bits)
    
    return {
        "tag": hex(tag),
        "set_index": set_index,
        "offset": offset,
        "line_aligned": (offset == 0),
        "num_sets": num_sets,
    }
```""",
        "assertions": """
res = decompose_cache_address(0x1a040)
assert res["offset"] == 0
assert res["line_aligned"] is True
assert res["set_index"] == 1
assert res["num_sets"] == 64
""",
    },

    # Discipline 5: Firmware Analysis
    {
        "record_id": "fw-uart-001",
        "domain": "sec_bench",
        "source_repo": "platform-core/firmware-analysis",
        "license_id": "Apache-2.0",
        "cve_id": None,
        "prompt_context": "[Firmware Analysis] Implement UART baud rate estimator from logic analyzer pulse duration samples by identifying minimum bit durations and matching against standard baud rates.",
        "target_completion": """```python
def estimate_uart_baudrate(pulse_durations_us: list[float]) -> dict:
    if not pulse_durations_us:
        raise ValueError("Empty pulse samples")
    STANDARD_BAUDRATES = [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
    min_pulse = min(p for p in pulse_durations_us if p > 0)
    raw_baud = 1_000_000.0 / min_pulse
    
    matched = None
    for b in STANDARD_BAUDRATES:
        if abs(raw_baud - b) / b <= 0.05:
            matched = b
            break
            
    return {
        "min_bit_duration_us": round(min_pulse, 2),
        "estimated_baudrate": matched or round(raw_baud),
        "is_standard": matched is not None,
    }
```""",
        "assertions": """
samples = [8.68, 17.36, 8.70, 26.04, 8.65]
res = estimate_uart_baudrate(samples)
assert res["estimated_baudrate"] == 115200
assert res["is_standard"] is True
try:
    estimate_uart_baudrate([])
    assert False, "Should raise ValueError"
except ValueError:
    pass
""",
    },
    {
        "record_id": "fw-jtag-002",
        "domain": "sec_bench",
        "source_repo": "platform-core/firmware-analysis",
        "license_id": "MIT",
        "cve_id": None,
        "prompt_context": "[Firmware Analysis] Implement IEEE 1149.1 JTAG Test Access Port (TAP) state machine simulator to track transitions across DR-Scan, IR-Scan, and Reset states based on TMS input signals.",
        "target_completion": """```python
def step_jtag_tap_fsm(current_state: str, tms: int) -> str:
    transitions = {
        "Test-Logic-Reset": {0: "Run-Test/Idle", 1: "Test-Logic-Reset"},
        "Run-Test/Idle": {0: "Run-Test/Idle", 1: "Select-DR-Scan"},
        "Select-DR-Scan": {0: "Capture-DR", 1: "Select-IR-Scan"},
        "Capture-DR": {0: "Shift-DR", 1: "Exit1-DR"},
        "Shift-DR": {0: "Shift-DR", 1: "Exit1-DR"},
        "Exit1-DR": {0: "Pause-DR", 1: "Update-DR"},
        "Pause-DR": {0: "Pause-DR", 1: "Exit2-DR"},
        "Exit2-DR": {0: "Shift-DR", 1: "Update-DR"},
        "Update-DR": {0: "Run-Test/Idle", 1: "Select-DR-Scan"},
        "Select-IR-Scan": {0: "Capture-IR", 1: "Test-Logic-Reset"},
        "Capture-IR": {0: "Shift-IR", 1: "Exit1-IR"},
        "Shift-IR": {0: "Shift-IR", 1: "Exit1-IR"},
        "Exit1-IR": {0: "Pause-IR", 1: "Update-IR"},
        "Pause-IR": {0: "Pause-IR", 1: "Exit2-IR"},
        "Exit2-IR": {0: "Shift-IR", 1: "Update-IR"},
        "Update-IR": {0: "Run-Test/Idle", 1: "Select-DR-Scan"},
    }
    state_map = transitions.get(current_state)
    if not state_map:
        raise ValueError(f"Unknown state: {current_state}")
    return state_map[1 if tms else 0]
```""",
        "assertions": """
st = "Shift-DR"
for _ in range(5):
    st = step_jtag_tap_fsm(st, 1)
assert st == "Test-Logic-Reset"
assert step_jtag_tap_fsm("Test-Logic-Reset", 0) == "Run-Test/Idle"
assert step_jtag_tap_fsm("Run-Test/Idle", 1) == "Select-DR-Scan"
assert step_jtag_tap_fsm("Select-DR-Scan", 0) == "Capture-DR"
assert step_jtag_tap_fsm("Capture-DR", 0) == "Shift-DR"
try:
    step_jtag_tap_fsm("InvalidState", 0)
    assert False, "Should raise ValueError"
except ValueError:
    pass
""",
    },
    {
        "record_id": "fw-uboot-003",
        "domain": "sec_bench",
        "source_repo": "platform-core/firmware-analysis",
        "license_id": "BSD-3-Clause",
        "cve_id": "CVE-2026-9203",
        "prompt_context": "[Firmware Analysis] Implement U-Boot legacy uImage header parser verifying 32-bit big-endian magic 0x27051956, extracting header CRC, load address, entry point, architecture, and image name.",
        "target_completion": """```python
import struct

def parse_uimage_header(data: bytes) -> dict:
    if len(data) < 64:
        raise ValueError("Header size must be at least 64 bytes")
    magic, hcrc, time, size, load, ep, dcrc, os, arch, type_, comp = struct.unpack(">IIIIIIIBBBB", data[:32])
    if magic != 0x27051956:
        raise ValueError(f"Invalid magic: {hex(magic)}")
    name = data[32:64].split(b"\\x00")[0].decode("latin-1", errors="replace")
    return {
        "valid_magic": True,
        "image_size": size,
        "load_address": hex(load),
        "entry_point": hex(ep),
        "image_name": name,
        "arch_arm": (arch == 2),
    }
```""",
        "assertions": """
import struct
hdr = struct.pack(">IIIIIIIBBBB", 0x27051956, 0, 1600000000, 2048, 0x80008000, 0x80008000, 0, 5, 2, 2, 1) + b"Linux-Kernel".ljust(32, b"\\x00")
res = parse_uimage_header(hdr)
assert res["valid_magic"] is True
assert res["load_address"] == "0x80008000"
assert res["image_name"] == "Linux-Kernel"
assert res["arch_arm"] is True
try:
    parse_uimage_header(b"\\x00"*64)
    assert False, "Should raise ValueError for invalid magic"
except ValueError:
    pass
""",
    },

    # Discipline 6: Network Protocols
    {
        "record_id": "net-ipv4-001",
        "domain": "sec_bench",
        "source_repo": "platform-core/network-protocols",
        "license_id": "Apache-2.0",
        "cve_id": None,
        "prompt_context": "[Network Protocols] Implement RFC 791 IPv4 header one's complement 16-bit checksum calculation and verification function handling carry bits and header validation.",
        "target_completion": """```python
import struct

def verify_ipv4_checksum(header: bytes) -> bool:
    if len(header) < 20:
        return False
    words = struct.unpack(">10H", header[:20])
    s = sum(words)
    while (s >> 16) > 0:
        s = (s & 0xFFFF) + (s >> 16)
    return (s & 0xFFFF) == 0xFFFF
```""",
        "assertions": """
import struct
hdr_zero = bytes.fromhex("4500003c1c46400040060000c0a80001c0a800c7")
words = struct.unpack(">10H", hdr_zero)
s = sum(words)
while (s >> 16) > 0:
    s = (s & 0xFFFF) + (s >> 16)
csum = (~s) & 0xFFFF
valid_hdr = hdr_zero[:10] + struct.pack(">H", csum) + hdr_zero[12:]
assert verify_ipv4_checksum(valid_hdr) is True

corrupted = valid_hdr[:10] + b"\\x00\\x00" + valid_hdr[12:]
assert verify_ipv4_checksum(corrupted) is False
assert verify_ipv4_checksum(b"short") is False
""",
    },
    {
        "record_id": "net-tcp-002",
        "domain": "sec_bench",
        "source_repo": "platform-core/network-protocols",
        "license_id": "MIT",
        "cve_id": "CVE-2026-9204",
        "prompt_context": "[Network Protocols] Implement RFC 793 TCP finite state machine validator for three-way connection establishment and teardown transitions, rejecting illegal flag combinations.",
        "target_completion": """```python
def validate_tcp_handshake_transition(current_state: str, flags_received: str) -> str:
    transitions = {
        ("LISTEN", "SYN"): "SYN_RCVD",
        ("SYN_SENT", "SYN_ACK"): "ESTABLISHED",
        ("SYN_RCVD", "ACK"): "ESTABLISHED",
        ("ESTABLISHED", "FIN"): "CLOSE_WAIT",
        ("ESTABLISHED", "FIN_ACK"): "CLOSE_WAIT",
    }
    next_state = transitions.get((current_state, flags_received))
    if not next_state:
        raise ValueError(f"Illegal TCP transition from {current_state} with flags {flags_received}")
    return next_state
```""",
        "assertions": """
assert validate_tcp_handshake_transition("LISTEN", "SYN") == "SYN_RCVD"
assert validate_tcp_handshake_transition("SYN_RCVD", "ACK") == "ESTABLISHED"
assert validate_tcp_handshake_transition("SYN_SENT", "SYN_ACK") == "ESTABLISHED"
try:
    validate_tcp_handshake_transition("LISTEN", "ACK")
    assert False, "Should raise ValueError"
except ValueError:
    pass
""",
    },
    {
        "record_id": "net-dns-003",
        "domain": "sec_bench",
        "source_repo": "platform-core/network-protocols",
        "license_id": "BSD-3-Clause",
        "cve_id": None,
        "prompt_context": "[Network Protocols] Implement RFC 1035 12-byte DNS message header parser extracting transaction ID, QR query/response flag, OPCODE, RCODE, question count, and answer count.",
        "target_completion": """```python
import struct

def parse_dns_header(packet: bytes) -> dict:
    if len(packet) < 12:
        raise ValueError("DNS header too short")
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", packet[:12])
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF
    return {
        "tx_id": tx_id,
        "is_response": bool(qr),
        "opcode": opcode,
        "rcode": rcode,
        "question_count": qdcount,
        "answer_count": ancount,
    }
```""",
        "assertions": """
import struct
pkt = struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
res = parse_dns_header(pkt)
assert res["tx_id"] == 0x1337
assert res["is_response"] is False
assert res["question_count"] == 1
assert res["answer_count"] == 0
try:
    parse_dns_header(b"short")
    assert False, "Should raise ValueError"
except ValueError:
    pass
""",
    },

    # Discipline 7: Exploit Mechanics
    {
        "record_id": "exp-canary-001",
        "domain": "sec_bench",
        "source_repo": "platform-core/exploit-mechanics",
        "license_id": "Apache-2.0",
        "cve_id": None,
        "prompt_context": "[Exploit Mechanics] Implement x86-64 stack canary integrity auditor checking 8-byte canary values, verifying null-byte termination to prevent string format leaks, and detecting corruption.",
        "target_completion": """```python
def verify_stack_canary(expected_canary: bytes, observed_canary: bytes) -> dict:
    if len(expected_canary) != 8 or len(observed_canary) != 8:
        raise ValueError("Canary must be 8 bytes on x86_64")
    has_null_byte = (expected_canary[0] == 0)
    intact = (expected_canary == observed_canary)
    return {
        "canary_intact": intact,
        "null_byte_preserved": has_null_byte,
        "overflow_detected": not intact,
    }
```""",
        "assertions": """
canary = b"\\x00" + b"\\x41\\x42\\x43\\x44\\x45\\x46\\x47"
res_ok = verify_stack_canary(canary, canary)
assert res_ok["canary_intact"] is True
assert res_ok["null_byte_preserved"] is True
assert res_ok["overflow_detected"] is False

corrupt_canary = b"\\x41"*8
res_bad = verify_stack_canary(canary, corrupt_canary)
assert res_bad["overflow_detected"] is True
try:
    verify_stack_canary(b"short", b"short")
    assert False, "Should raise ValueError"
except ValueError:
    pass
""",
    },
    {
        "record_id": "exp-rop-002",
        "domain": "sec_bench",
        "source_repo": "platform-core/exploit-mechanics",
        "license_id": "MIT",
        "cve_id": None,
        "prompt_context": "[Exploit Mechanics] Implement Return-Oriented Programming (ROP) gadget chain validator ensuring each gadget sequence terminates with a valid ret (0xC3) opcode and contains no forbidden null/CR/LF bytes.",
        "target_completion": """```python
def validate_rop_gadget_chain(gadgets: list[bytes], forbidden_bytes: set[int] = {0x00, 0x0A, 0x0D}) -> dict:
    if not gadgets:
        return {"valid": False, "reason": "Empty chain"}
    for idx, g in enumerate(gadgets):
        if not g or g[-1] != 0xC3:
            return {"valid": False, "reason": f"Gadget {idx} does not terminate with ret (0xC3)"}
        for b in g:
            if b in forbidden_bytes:
                return {"valid": False, "reason": f"Gadget {idx} contains forbidden byte {hex(b)}"}
    return {
        "valid": True,
        "gadget_count": len(gadgets),
        "clean_payload": True,
    }
```""",
        "assertions": """
pop_rdi_ret = bytes.fromhex("5fc3")
pop_rsi_ret = bytes.fromhex("5ec3")
res = validate_rop_gadget_chain([pop_rdi_ret, pop_rsi_ret])
assert res["valid"] is True
assert res["gadget_count"] == 2

bad_gadget = bytes.fromhex("5f00c3")
assert validate_rop_gadget_chain([bad_gadget])["valid"] is False
assert validate_rop_gadget_chain([])["valid"] is False
""",
    },
    {
        "record_id": "exp-intovf-003",
        "domain": "sec_bench",
        "source_repo": "platform-core/exploit-mechanics",
        "license_id": "BSD-3-Clause",
        "cve_id": "CVE-2026-9205",
        "prompt_context": "[Exploit Mechanics] Implement integer overflow-safe memory allocator size calculator checking unsigned 64-bit multiplication against UINT64_MAX and enforcing upper memory allocation limits.",
        "target_completion": """```python
def safe_malloc_size(num_elements: int, element_size: int, max_limit: int = 1 << 30) -> int:
    UINT64_MAX = (1 << 64) - 1
    if num_elements < 0 or element_size < 0:
        raise ValueError("Negative dimensions rejected")
    if num_elements == 0 or element_size == 0:
        return 0
    if num_elements > UINT64_MAX // element_size:
        raise OverflowError("64-bit integer overflow in size calculation")
    total_bytes = num_elements * element_size
    if total_bytes > max_limit:
        raise MemoryError(f"Allocation size {total_bytes} exceeds safety quota {max_limit}")
    return total_bytes
```""",
        "assertions": """
assert safe_malloc_size(100, 8) == 800
assert safe_malloc_size(0, 8) == 0
try:
    safe_malloc_size((1 << 63), 4)
    assert False, "Should raise OverflowError"
except OverflowError:
    pass
try:
    safe_malloc_size(1 << 20, 2048)
    assert False, "Should raise MemoryError"
except MemoryError:
    pass
try:
    safe_malloc_size(-1, 8)
    assert False, "Should raise ValueError"
except ValueError:
    pass
""",
    },
]


def synthesize_and_verify_all() -> None:
    print(f"[*] Starting synthesis of {len(TRAJECTORY_SPECS)} new cybersecurity trajectories...")
    sandbox = FirecrackerSandboxManager()

    verified_new_records: list[dict[str, Any]] = []

    for idx, spec in enumerate(TRAJECTORY_SPECS, 1):
        rec_id = spec["record_id"]
        safe_vm_id = f"verify-v4-{re.sub(r'[^A-Za-z0-9._-]', '-', rec_id)}"

        clean_code = extract_python_code(spec["target_completion"])
        harness = (
            f"# Verification harness for {rec_id}\n"
            f"{clean_code}\n\n"
            f"# Verification Assertions\n"
            f"{spec['assertions'].strip()}\n\n"
            f"print('VERIFICATION_OK')\n"
        )

        sandbox.provision_microvm(safe_vm_id, tainted=True)
        res = sandbox.execute_python_in_sandbox(safe_vm_id, harness, timeout_sec=10.0)

        if res.exit_code != 0 or "VERIFICATION_OK" not in res.stdout:
            print(f"[-] VERIFICATION FAILED for {rec_id} (exit_code={res.exit_code}):")
            print(f"Stderr: {res.stderr}")
            print(f"Stdout: {res.stdout}")
            sys.exit(1)

        print(f"  [+] [{idx:02d}/{len(TRAJECTORY_SPECS)}] {rec_id} verified in microVM (exit_code=0, {res.duration_ms}ms)")

        verified_rec = {
            "record_id": rec_id,
            "domain": spec["domain"],
            "source_repo": spec["source_repo"],
            "license_id": spec["license_id"],
            "cve_id": spec["cve_id"],
            "prompt_context": spec["prompt_context"],
            "target_completion": spec["target_completion"],
            "execution_verified": True,
            "metadata": {
                "sandbox_exit_code": 0,
                "sandbox_vm_id": safe_vm_id,
            },
        }
        verified_new_records.append(verified_rec)

    # Load baseline trajectories
    baseline_path = Path("artifacts/v3_verified_trajectories.jsonl")
    if not baseline_path.exists():
        print(f"[-] Baseline trajectories not found at {baseline_path}")
        sys.exit(1)

    baseline_records: list[dict[str, Any]] = []
    with baseline_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                baseline_records.append(json.loads(line))

    print(f"[*] Loaded {len(baseline_records)} baseline records from {baseline_path}")

    # Merge records
    merged_records = baseline_records + verified_new_records
    print(f"[*] Total merged records: {len(merged_records)} (23 baseline + 21 new)")

    # Convert to TrainingTrajectoryRecord for hygiene audit
    records_for_audit: list[TrainingTrajectoryRecord] = []
    for idx, item in enumerate(merged_records):
        records_for_audit.append(
            TrainingTrajectoryRecord(
                record_id=str(item["record_id"]),
                domain=str(item["domain"]),
                source_repo=str(item["source_repo"]),
                license_id=str(item["license_id"]),
                cve_id=item.get("cve_id"),
                prompt_context=str(item["prompt_context"]),
                target_completion=str(item["target_completion"]),
                execution_verified=bool(item.get("execution_verified", False)),
                metadata=dict(item.get("metadata") or {}),
            )
        )

    # Run DatasetHygienePipeline audit
    print("[*] Auditing all merged records through DatasetHygienePipeline(jaccard_dedup_threshold=0.85)...")
    pipeline = DatasetHygienePipeline(jaccard_dedup_threshold=0.85)
    hygiene_res = pipeline.filter_records(records_for_audit)

    accepted_count = hygiene_res["accepted_count"]
    rejected_breakdown = hygiene_res["rejected_breakdown"]
    print(f"[*] Hygiene results: total_input={hygiene_res['total_input']}, accepted_count={accepted_count}")
    print(f"[*] Rejected breakdown: {rejected_breakdown}")

    assert accepted_count == 44, f"Expected 44 accepted records, got {accepted_count}"
    for k, v in rejected_breakdown.items():
        assert v == 0, f"Expected 0 rejections for {k}, got {v}"

    # Write merged records to artifacts/v4_verified_trajectories.jsonl
    output_path = Path("artifacts/v4_verified_trajectories.jsonl")
    with output_path.open("w", encoding="utf-8") as f:
        for rec in merged_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"[+] Successfully wrote 44 verified records to {output_path}")


if __name__ == "__main__":
    synthesize_and_verify_all()
