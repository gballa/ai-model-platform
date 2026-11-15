# Development & Engineering Guides Index

This directory contains practical playbooks for setting up, configuring, extending, debugging, and maintaining `platform-core`.

---

## Guides

| Guide | Activity Covered |
| :--- | :--- |
| [Getting Started](getting-started.md) | Rapid local onboarding, running the CLI, executing workflows, and running the test suite. |
| [Environment Setup](environment-setup.md) | Python 3.11+ virtual environment setup, editable package installation, and workstation vs. cluster dependencies. |
| [Configuration Reference](configuration.md) | Complete reference for dataclasses (`CustomModelConfig`, `ServingEndpointConfig`, `RoutingRequest`), CLI flags, SQLite pragmas, and sandbox environment variable sanitization. |
| [Development Workflow & Extending the Platform](development-workflow.md) | Adding new MCP tools, registering custom models, extending domains, running the `-W error` test gate, and applying the Documentation Impact Checklist. |
| [Troubleshooting Playbook](troubleshooting.md) | Diagnosing and resolving common exceptions (`PickleSupplyChainError`, `SafetensorsValidationError`, `PermissionError`, `MemoryError`, `ValueError`, SQLite locking). |

---

## Related Documentation

- [Contributing Guidelines](../../CONTRIBUTING.md)
- [Documentation Standards Policy](../DOCUMENTATION_STANDARDS.md)
- [AI Agent Documentation Policy](../AI_DOCUMENTATION_POLICY.md)
- [Operational Playbooks (`docs/guides/`)](../guides/README.md)
