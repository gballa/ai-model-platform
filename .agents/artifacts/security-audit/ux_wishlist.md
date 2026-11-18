# UX Improvement Wishlist for CLI and Agent Transparency Dashboard

## Overview
This document outlines UX improvements for the CLI and Agent Transparency Dashboard, with a specific focus on cross-platform portability and API-first control for secondary integration layers.

## 1. CLI Improvements
- **Standardized Configuration:** Enforce `AGY_CONFIG_DIR` and `AGY_CACHE_DIR` usage across all platforms to ensure consistent behavior on macOS, Linux, and Windows.
- **API-Equivalent Commands:** Ensure every CLI operation has a corresponding JSON/YAML-output format, allowing programmatic access by external systems.
- **Cross-Platform Plugin/Skill Management:** Standardize plugin/skill installation and management mechanisms across all operating systems to avoid path-related failures.

## 2. Agent Transparency Dashboard Improvements
- **API-First Telemetry Stream:** Expose real-time agent state, telemetry, and logs via a local gRPC or WebSocket server, enabling external monitoring tools to hook into the agent's stream.
- **Session Snapshots:** Implement an API-based mechanism to export and import full agent session states, facilitating portability and reproducibility.
- **Read-Only Mode:** Introduce a secure, read-only mode for the dashboard, allowing external management platforms to observe agent activity without risking accidental input.

## 3. Portability & Integration
- **Platform-Agnostic Setup:** Provide a single-binary distribution (or containerized approach) for the CLI and Dashboard that encapsulates all dependencies.
- **Secondary Integration Hooks:** Define clear, documented hooks (e.g., event emitters) that secondary tools can use to trigger actions or respond to agent events.
