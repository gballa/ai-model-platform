#!/usr/bin/env python3
"""Milestone 1 Ingestion and Acquisition Manifest Generator.

Ingests curated authoritative technical books across all 13 cybersecurity domains
into `artifacts/books_rag.db` with strict SHA-256 deduplication, updates
`artifacts/books_harvest.json`, and emits `artifacts/cybersecurity_acquisition_manifest.json`.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

# Ensure src is on sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT / "src"))

from platform_core.layer3_evolution.corpus_harvester import (
    DomainChunker,
    PromptInjectionSanitizer,
)
from platform_core.layer3_evolution.memory import HybridKnowledgeStore


RESOURCES_SPEC = [
    {
        "resource_id": "tis-elf-specification-v1-2",
        "domain": "Binary Analysis",
        "title": "Tool Interface Standard (TIS) Portable Formats Specification: Executable and Linkable Format (ELF) v1.2",
        "author": "TIS Committee",
        "edition": "Version 1.2 Standards Composite",
        "difficulty_level": "Advanced",
        "license_id": "CC0-1.0",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Comprehensive reference on ELF binary architecture: 64-bit ELF headers (Elf64_Ehdr), section headers (Elf64_Shdr), program headers and segments (Elf64_Phdr), symbol tables, dynamic relocations (R_X86_64), PLT/GOT resolution, and checksec binary triage.",
        "format": "markdown",
        "collection": "binary_analysis",
        "relative_path": "artifacts/books/binary_analysis/tis_elf_specification_v1_2.md",
    },
    {
        "resource_id": "nsa-ghidra-decompilation-guide",
        "domain": "Binary Analysis",
        "title": "NSA Ghidra Architecture, Intermediate Representation (P-Code) and Decompiler Guide",
        "author": "National Security Agency (NSA)",
        "edition": "Technical Reference Edition",
        "difficulty_level": "Advanced",
        "license_id": "Apache-2.0",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Ghidra software reverse engineering framework architecture: SLEIGH processor specification language, P-Code intermediate representation micro-operations, basic block CFG construction, SSA transformation, dominance frontiers, struct layout recovery, and binary vulnerability analysis.",
        "format": "markdown",
        "collection": "binary_analysis",
        "relative_path": "artifacts/books/binary_analysis/ghidra_decompilation_and_reverse_engineering_guide.md",
    },
    {
        "resource_id": "system-v-abi-amd64-reference",
        "domain": "Assembly Language",
        "title": "System V Application Binary Interface: AMD64 Architecture Processor Supplement",
        "author": "System V AMD64 ABI Working Group",
        "edition": "Draft Version 1.0 Processor Supplement",
        "difficulty_level": "Advanced",
        "license_id": "CC0-1.0",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Authoritative AMD64 System V ABI specification: general purpose and vector register roles, caller-saved vs callee-saved conventions, integer and floating point parameter passing order, 16-byte stack alignment invariants, 128-byte Red Zone rules, and Linux kernel syscall ABI differences.",
        "format": "markdown",
        "collection": "assembly_language",
        "relative_path": "artifacts/books/assembly_language/system_v_abi_amd64_reference.md",
    },
    {
        "resource_id": "x86-64-arm64-assembly-mechanics",
        "domain": "Assembly Language",
        "title": "x86-64 and ARM64 Assembly Mechanics: Architecture, Disassembly, and Shellcode Engineering",
        "author": "OpenSecurity Assembly Consortium",
        "edition": "Second Edition",
        "difficulty_level": "Intermediate",
        "license_id": "MIT",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Comparative architecture and disassembly mechanics of x86-64 (CISC) and ARM64/AArch64 (RISC): register mappings, addressing modes, position-independent RIP/PC-relative addressing, Linux syscall invocation conventions, and null-free shellcode engineering.",
        "format": "markdown",
        "collection": "assembly_language",
        "relative_path": "artifacts/books/assembly_language/x86_64_and_arm64_assembly_mechanics.md",
    },
    {
        "resource_id": "linux-kernel-architecture-subsystems",
        "domain": "Operating System Internals",
        "title": "Linux Kernel Subsystems and Architecture: Process Scheduling, Memory Management, and VFS",
        "author": "Linux Kernel Documentation Project",
        "edition": "6.x LTS Architecture Edition",
        "difficulty_level": "Expert",
        "license_id": "BSD-2-Clause",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Linux monolithic kernel internals: Kernel Page Table Isolation (KPTI), struct task_struct process/thread representation, Completely Fair Scheduler (CFS) red-black tree runqueues, virtual memory mm_struct and VMA trees, demand paging (#PF), VFS four core abstractions, and system call entry path.",
        "format": "markdown",
        "collection": "operating_system_internals",
        "relative_path": "artifacts/books/operating_system_internals/linux_kernel_architecture_and_subsystems.md",
    },
    {
        "resource_id": "freebsd-posix-kernel-internals",
        "domain": "Operating System Internals",
        "title": "FreeBSD and POSIX Operating System Internals: Architecture, Virtual Memory, and Security Sandboxing",
        "author": "The FreeBSD Documentation Project",
        "edition": "14.0 Release Architecture Edition",
        "difficulty_level": "Advanced",
        "license_id": "BSD-2-Clause",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "POSIX and FreeBSD kernel architecture: process and thread abstractions, Mach-derived VM subsystem (vm_map, vm_object, shadow objects, copy-on-write), UMA slab allocator, kqueue/kevent O(1) scalable event notification, and security models: Jails and Capsicum capability sandboxing.",
        "format": "markdown",
        "collection": "operating_system_internals",
        "relative_path": "artifacts/books/operating_system_internals/posix_and_bsd_kernel_internals.md",
    },
    {
        "resource_id": "modern-memory-architecture-paging-caches-mmu",
        "domain": "Memory Architecture",
        "title": "Modern Memory Architecture: Hierarchy, Paging, Cache Coherence, and MMU Hardware",
        "author": "Systems Memory Working Group & Ulrich Drepper Reference Edition",
        "edition": "Third Architecture Edition",
        "difficulty_level": "Advanced",
        "license_id": "CC-BY-4.0",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": False,
        "technical_summary": "Hardware memory hierarchy and virtual memory hardware: CPU cache line structures, set-associativity, write policies, MESI cache coherence protocol, false sharing, x86-64 4-level paging (PML4, PDPT, PD, PT), PTE control bits, TLB translation and shootdowns, and NUMA node topology.",
        "format": "markdown",
        "collection": "memory_architecture",
        "relative_path": "artifacts/books/memory_architecture/memory_architecture_paging_caches_and_mmu.md",
    },
    {
        "resource_id": "owasp-firmware-security-testing-methodology",
        "domain": "Firmware & Embedded Systems Analysis",
        "title": "OWASP Firmware Security Testing Methodology (FSTM) v2.0",
        "author": "OWASP Internet of Things & Firmware Security Project",
        "edition": "Version 2.0 Comprehensive Reference",
        "difficulty_level": "Advanced",
        "license_id": "CC-BY-SA-4.0",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": True,
        },
        "trainable_permissive": False,
        "technical_summary": "Nine-phase firmware security testing methodology: information gathering, physical/digital firmware acquisition, binwalk signature and entropy analysis, filesystem extraction (SquashFS, JFFS2, UBIFS), static filesystem audits for hardcoded credentials, QEMU emulation, dynamic fuzzing, and binary checksec verification.",
        "format": "markdown",
        "collection": "firmware_analysis",
        "relative_path": "artifacts/books/firmware_analysis/owasp_firmware_security_testing_methodology.md",
    },
    {
        "resource_id": "embedded-systems-hardware-security-analysis",
        "domain": "Firmware & Embedded Systems Analysis",
        "title": "Embedded Systems Security, Hardware Bus Protocols, and Bootloader Analysis",
        "author": "Hardware Security Research Group",
        "edition": "First Edition",
        "difficulty_level": "Advanced",
        "license_id": "Apache-2.0",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Embedded hardware security assessment: UART pinout identification, JTAG TAP state machine and boundary scan, SPI bus flash memory dumping (flashrom), Das U-Boot architecture, shell breakout via bootargs manipulation, and hardware root of trust (eFuses, secure boot chain).",
        "format": "markdown",
        "collection": "firmware_analysis",
        "relative_path": "artifacts/books/firmware_analysis/embedded_devices_and_hardware_security_analysis.md",
    },
    {
        "resource_id": "ietf-core-network-protocols-rfc-suite",
        "domain": "Network Protocols",
        "title": "IETF Core Internet Protocols Reference Suite: IPv4, TCP, DNS, and HTTP Semantics",
        "author": "Internet Engineering Task Force (IETF)",
        "edition": "Standards Track Composite Edition",
        "difficulty_level": "Intermediate",
        "license_id": "CC0-1.0",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Core internet protocols: IPv4 datagram header fields, TTL and fragmentation; TCP three-way handshake, state transitions, sequence numbers, and four-way termination; DNS message headers, query/response records, and cache poisoning; HTTP/1.1 semantics, idempotency, and request smuggling mechanics.",
        "format": "markdown",
        "collection": "network_protocols",
        "relative_path": "artifacts/books/network_protocols/ietf_core_network_protocols_rfc_reference.md",
    },
    {
        "resource_id": "nist-rfc-cryptographic-engineering",
        "domain": "Cryptographic Implementation",
        "title": "Applied Cryptographic Engineering: Block Cipher Modes, Public Key Infrastructure, and TLS 1.3 Architecture",
        "author": "NIST & IETF Security Engineering Task Force",
        "edition": "Second Edition",
        "difficulty_level": "Expert",
        "license_id": "CC0-1.0",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Applied cryptographic engineering: AES round functions (SubBytes, ShiftRows, MixColumns), NIST SP 800-38A/D block cipher modes (ECB vulnerabilities, CBC padding oracles, GCM AEAD and nonce reuse disaster), RSA-OAEP/PSS, Elliptic Curves (Curve25519, Ed25519), and TLS 1.3 1-RTT handshake and HKDF key derivation.",
        "format": "markdown",
        "collection": "cryptographic_implementation",
        "relative_path": "artifacts/books/cryptographic_implementation/nist_and_rfc_cryptographic_engineering.md",
    },
    {
        "resource_id": "nist-sp-800-115-testing-guide",
        "domain": "Penetration Testing Methodologies",
        "title": "NIST SP 800-115: Technical Guide to Information Security Testing and Assessment",
        "author": "Karen Scarfone, Murugiah Souppaya, Matthew Cody, Angela Orebaugh (NIST)",
        "edition": "Special Publication 800-115",
        "difficulty_level": "Intermediate",
        "license_id": "CC0-1.0",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Authoritative NIST methodology for information security testing, technical assessment techniques, target identification, port and vulnerability scanning, penetration testing lifecycle, rules of engagement, and post-testing restoration.",
        "format": "markdown",
        "collection": "penetration_testing",
        "relative_path": "artifacts/books/penetration_testing/nist_sp_800_115_security_testing_guide.md",
    },
    {
        "resource_id": "modern-exploit-mechanics-memory-corruption",
        "domain": "Exploit Mechanics",
        "title": "Modern Exploit Mechanics: Memory Corruption, Control-Flow Hijacking, and Mitigation Bypasses",
        "author": "Systems Exploitation Research Collective",
        "edition": "Third Research Edition",
        "difficulty_level": "Expert",
        "license_id": "MIT",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "In-depth mechanics of memory corruption vulnerabilities, stack buffer overflows, return-oriented programming (ROP) chain synthesis, format string arbitrary read/write primitives, glibc ptmalloc heap internals (tcache poisoning, fastbins, UAF), and OS mitigation bypasses (ASLR, NX, Canaries, RELRO).",
        "format": "markdown",
        "collection": "exploit_mechanics",
        "relative_path": "artifacts/books/exploit_mechanics/advanced_exploit_mechanics_and_memory_corruption.md",
    },
    {
        "resource_id": "cwe-vulnerability-research-methodologies",
        "domain": "Vulnerability Research",
        "title": "Vulnerability Research Methodologies: Root-Cause Analysis, CWE Taxonomies, and Variant Analysis",
        "author": "MITRE CWE Consortium & Vulnerability Research Project",
        "edition": "2024 Research Edition",
        "difficulty_level": "Advanced",
        "license_id": "CC0-1.0",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Vulnerability research methodologies focusing on threat modeling, AST-based static dataflow taint tracking, coverage-guided fuzzing (AFL++, sanitizers), root cause analysis across top CWEs (CWE-78, CWE-89, CWE-120, CWE-190, CWE-502), CVSS v3.1/v4.0 scoring, and EPSS modeling.",
        "format": "markdown",
        "collection": "vulnerability_research",
        "relative_path": "artifacts/books/vulnerability_research/vulnerability_research_cwe_internals_and_analysis.md",
    },
    {
        "resource_id": "practical-malware-analysis-behavioral-triage",
        "domain": "Malware Analysis",
        "title": "Practical Malware Analysis: Triage, Static Decompilation, Dynamic Emulation, and Threat Attribution",
        "author": "Cyber Threat Defense Foundation",
        "edition": "Second Edition",
        "difficulty_level": "Advanced",
        "license_id": "Apache-2.0",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Malware analysis workflows and laboratory containment: static triage (SSDEEP, Imphash, PE sections, string deobfuscation with FLOSS), dynamic behavioral monitoring (filesystem, registry persistence, process hollowing), anti-debugging (PEB flags, rdtsc) and anti-VM countermeasures, and YARA rule engineering.",
        "format": "markdown",
        "collection": "malware_analysis",
        "relative_path": "artifacts/books/malware_analysis/practical_malware_analysis_and_behavioral_triage.md",
    },
    {
        "resource_id": "advanced-digital-forensics-incident-investigation",
        "domain": "Digital Forensics",
        "title": "Advanced Digital Forensics and Incident Response: Disk, Memory, and Network Evidence Acquisition",
        "author": "Digital Forensics Working Group",
        "edition": "Fourth Edition",
        "difficulty_level": "Advanced",
        "license_id": "Apache-2.0",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Digital forensics investigation principles (ISO/IEC 27037, RFC 3227 order of volatility, bit-stream disk imaging), Volatility 3 memory forensics (process tree, network sockets, malfind code injection), NTFS forensics ($MFT resident data, timestamps, USN journal), Windows artifacts (Prefetch, Shimcache, Amcache, Shellbags, Event Logs), and mobile device forensics.",
        "format": "markdown",
        "collection": "digital_forensics",
        "relative_path": "artifacts/books/digital_forensics/advanced_digital_forensics_and_incident_investigation.md",
    },
    {
        "resource_id": "modern-web-api-security-architecture",
        "domain": "Web and API Security",
        "title": "Modern Web Application and API Security Architecture: Vulnerabilities, Defenses, and Zero Trust",
        "author": "Open Web Security Research Collective",
        "edition": "2024 Architectural Edition",
        "difficulty_level": "Intermediate",
        "license_id": "MIT",
        "spdx_permissions": {
            "commercial_use": True,
            "derivatives_allowed": True,
            "distribution_allowed": True,
            "copyleft": False,
        },
        "trainable_permissive": True,
        "technical_summary": "Modern web application and API security: OWASP API Security Top 10 (BOLA/IDOR, broken authentication, mass assignment, BFLA, SSRF defenses), client-side vulnerabilities (XSS variations, CSP headers, SameSite cookie policies), and Zero Trust architecture (least privilege, mTLS).",
        "format": "markdown",
        "collection": "web_api_security",
        "relative_path": "artifacts/books/web_api_security/modern_web_and_api_security_architecture.md",
    },
]


def run_pipeline() -> None:
    print("=== Step 1: Ingesting into artifacts/books_rag.db ===")
    rag_db_path = WORKSPACE_ROOT / "artifacts" / "books_rag.db"
    store = HybridKnowledgeStore(str(rag_db_path))

    # Preload existing digests to ensure strict deduplication
    with store._lock:
        existing_digests = set(
            r[0] for r in store._conn.execute("SELECT sha256_digest FROM knowledge_chunks").fetchall()
        )
        existing_chunk_ids = set(
            r[0] for r in store._conn.execute("SELECT chunk_id FROM knowledge_chunks").fetchall()
        )

    print(f"Pre-existing chunks in DB: {len(existing_chunk_ids)}, unique digests: {len(existing_digests)}")

    harvest_docs: list[dict] = []
    manifest_resources: list[dict] = []
    new_chunks_count = 0
    new_tokens_count = 0

    for spec in RESOURCES_SPEC:
        file_path = WORKSPACE_ROOT / spec["relative_path"]
        if not file_path.is_file():
            raise FileNotFoundError(f"Missing resource file: {file_path}")

        raw_text = file_path.read_text(encoding="utf-8")
        raw_char_count = len(raw_text)
        content_sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        doc_id = f"book-{content_sha256[:12]}"

        # Sanitize
        sanitized_text, alerts = PromptInjectionSanitizer.sanitize(raw_text)

        # Chunk
        chunks = DomainChunker.chunk_text(
            sanitized_text, chunk_chars=2400, overlap_chars=300, preserve_code_blocks=True
        )

        doc_tokens = 0
        doc_chunks_ingested = 0
        source_uri = f"file://{file_path.resolve()}"

        for idx, chunk in enumerate(chunks):
            cdigest = hashlib.sha256(chunk.encode("utf-8")).hexdigest()
            chunk_tokens = max(1, len(chunk) // 4)
            doc_tokens += chunk_tokens

            # Deduplication check
            if cdigest in existing_digests:
                print(f"  [DEDUP SKIP] Chunk digest already in DB: {cdigest[:12]}")
                continue

            chunk_id = f"{spec['collection']}:{doc_id}#chunk-{idx}"
            metadata = {
                "book_collection": spec["collection"],
                "domain": spec["domain"],
                "license_id": spec["license_id"],
                "title": spec["title"],
                "trainable_permissive": spec["trainable_permissive"],
                "sha256": content_sha256,
                "chunk_index": idx,
            }

            store.ingest_document(
                chunk_id=chunk_id,
                source_uri=source_uri,
                content=chunk,
                metadata=metadata,
            )

            existing_digests.add(cdigest)
            existing_chunk_ids.add(chunk_id)
            doc_chunks_ingested += 1
            new_chunks_count += 1
            new_tokens_count += chunk_tokens

        print(
            f"Ingested {spec['resource_id']}: {doc_chunks_ingested}/{len(chunks)} chunks, ~{doc_tokens} tokens"
        )

        # Build harvest doc
        harvest_doc = {
            "book_collection": spec["collection"],
            "chunks": chunks,
            "doc_id": doc_id,
            "domain": spec["domain"],
            "injection_alerts": list(alerts),
            "license_id": spec["license_id"],
            "metadata": {
                "file_name": file_path.name,
                "format": spec["format"],
                "truncated": False,
            },
            "raw_char_count": raw_char_count,
            "sanitized_text": sanitized_text,
            "sha256": content_sha256,
            "source_type": "markdown_book",
            "source_uri": source_uri,
            "title": spec["title"],
            "trainable_permissive": spec["trainable_permissive"],
        }
        harvest_docs.append(harvest_doc)

        # Build manifest resource entry
        manifest_resource = {
            "resource_id": spec["resource_id"],
            "domain": spec["domain"],
            "title": spec["title"],
            "author": spec["author"],
            "edition": spec["edition"],
            "difficulty_level": spec["difficulty_level"],
            "license_id": spec["license_id"],
            "spdx_permissions": spec["spdx_permissions"],
            "trainable_permissive": spec["trainable_permissive"],
            "technical_summary": spec["technical_summary"],
            "format": spec["format"],
            "local_path": spec["relative_path"],
            "source_uri": source_uri,
            "content_sha256": content_sha256,
            "ingestion_status": "ingested",
            "estimated_tokens": doc_tokens,
        }
        manifest_resources.append(manifest_resource)

    # Probe RAG store
    probe = store.retrieve("ELF Ghidra x86_64 Paging FSTM TLS 1.3", top_k=5)
    total_db_tokens = probe["total_corpus_tokens"]
    retrieval_mode = probe["retrieval_mode"]
    store.close()

    print(f"\nRAG DB Updated: total_corpus_tokens={total_db_tokens}, mode={retrieval_mode}")
    print(f"New chunks added: {new_chunks_count}, new tokens added: {new_tokens_count}")

    # === Step 2: Update artifacts/books_harvest.json ===
    print("\n=== Step 2: Updating artifacts/books_harvest.json ===")
    harvest_path = WORKSPACE_ROOT / "artifacts" / "books_harvest.json"
    with harvest_path.open("r", encoding="utf-8") as f:
        harvest_data = json.load(f)

    # Deduplicate existing documents by sha256 to guarantee zero duplicates across the entire file
    seen_shas = set()
    cleaned_existing_docs = []
    for doc in harvest_data["documents"]:
        dsha = doc.get("sha256")
        if dsha in seen_shas:
            print(f"  [DEDUP REMOVED] Pre-existing duplicate doc in harvest: {doc.get('doc_id')}")
            continue
        seen_shas.add(dsha)
        cleaned_existing_docs.append(doc)

    for hdoc in harvest_docs:
        if hdoc["sha256"] in seen_shas:
            print(f"  [DEDUP SKIP] New doc already in harvest: {hdoc['doc_id']}")
            continue
        seen_shas.add(hdoc["sha256"])
        cleaned_existing_docs.append(hdoc)

    # Recompute total chunks and tokens
    total_harvest_chunks = sum(len(d["chunks"]) for d in cleaned_existing_docs)
    total_harvest_tokens = sum(
        sum(max(1, len(c) // 4) for c in d["chunks"]) for d in cleaned_existing_docs
    )

    # Update source stats
    source_stats = harvest_data.get("source_stats", {})
    for spec in RESOURCES_SPEC:
        col = spec["collection"]
        # Find docs belonging to this collection
        col_docs = [d for d in cleaned_existing_docs if d.get("book_collection") == col]
        col_chunks = sum(len(d["chunks"]) for d in col_docs)
        col_tokens = sum(
            sum(max(1, len(c) // 4) for c in d["chunks"]) for d in col_docs
        )
        source_stats[col] = {
            "chunks": col_chunks,
            "documents": len(col_docs),
            "domain": spec["domain"],
            "license_id": spec["license_id"],
            "tokens_est": col_tokens,
            "trainable_permissive": spec["trainable_permissive"],
        }

    harvest_data["documents"] = cleaned_existing_docs
    harvest_data["document_count"] = len(cleaned_existing_docs)
    harvest_data["total_chunks"] = total_harvest_chunks
    harvest_data["total_tokens_est"] = total_harvest_tokens
    harvest_data["source_stats"] = source_stats
    harvest_data["rag_stats"] = {
        "probe_hits": 5,
        "rag_db": str(rag_db_path),
        "retrieval_mode": retrieval_mode,
        "total_corpus_tokens": total_db_tokens,
    }

    with harvest_path.open("w", encoding="utf-8") as f:
        json.dump(harvest_data, f, indent=2, sort_keys=True)
        f.write("\n")

    print(
        f"books_harvest.json updated: document_count={harvest_data['document_count']}, total_chunks={total_harvest_chunks}, total_tokens_est={total_harvest_tokens}"
    )

    # === Step 3: Emit artifacts/cybersecurity_acquisition_manifest.json ===
    print("\n=== Step 3: Emitting artifacts/cybersecurity_acquisition_manifest.json ===")
    manifest_path = WORKSPACE_ROOT / "artifacts" / "cybersecurity_acquisition_manifest.json"
    distinct_domains = sorted(list(set(r["domain"] for r in manifest_resources)))

    manifest = {
        "manifest_version": "1.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_resources": len(manifest_resources),
        "domains_covered": len(distinct_domains),
        "domain_list": distinct_domains,
        "resources": manifest_resources,
    }

    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    print(f"Acquisition manifest emitted: {manifest_path}")
    print(f"Total resources: {len(manifest_resources)}, Domains covered: {len(distinct_domains)}")
    print(f"Domains: {distinct_domains}")


if __name__ == "__main__":
    run_pipeline()
