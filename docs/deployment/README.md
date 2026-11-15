# Build, Packaging & Production Deployment Guide

---

## 1. Purpose

Provide step-by-step instructions for packaging custom specialist models (`.safetensors` + `.manifest.json`), generating `SGLang v0.5.19` and `vLLM v0.28` GPU inference launch commands, generating `PyTorch FSDP2` and `DeepSpeed ZeRO-3` distributed training specifications, and emitting Kubernetes `agent-sandbox` (`SandboxTemplate` & `SandboxClaim`) and Squid firewall configurations.

---

## 2. Prerequisites

- Local environment: Python `>= 3.11` with `.venv` initialized (`PYTHONPATH=src .venv/bin/python`).
- Optional target cluster infrastructure (when deploying generated artifacts to production):
  - GPU inference nodes running `SGLang v0.5.19+` or `vLLM v0.28+`.
  - Kubernetes cluster with `kubernetes-sigs/agent-sandbox` controller and `kata-fc` (Kata Containers + Firecracker v1.12+ KVM) `RuntimeClass`.
  - Squid proxy service (`cybergym-squid-proxy.ai-platform-sandboxes.svc.cluster.local:3128`).

---

## 3. Required Configuration

- Model checkpoints must be packaged as `.safetensors` files passing `SafetensorsValidator` and licensed under an `APPROVED_COMMERCIAL` SPDX identifier (`Apache-2.0`, `MIT`, `BSD-3-Clause`).

---

## 4. Step-by-Step Instructions

1. **Build and Export the Custom Model Bundle**: Run `create-custom-model` (or `CustomModelPipeline.build_custom_model()`) with `--output-dir` to atomically generate `<model-id>.safetensors` and `<model-id>.manifest.json`.
2. **Generate SGLang / vLLM Serving Launch Commands**: Read `serving_launch_args` from `<model-id>.manifest.json` or call `RadixPrefixCacheSimulator.build_default_pool_configs()`.
3. **Generate Kubernetes `SandboxTemplate` & `SandboxClaim` Manifests**: Call `K8sAgentSandboxGenerator.build_sandbox_template()` and `build_sandbox_claim()`.
4. **Generate the Squid Egress Firewall Configuration**: Call `CyberGymFirewall.generate_squid_conf()`.

---

## 5. Verified Commands and Examples

### Generating Production Serving, Kubernetes Sandbox, and Firewall Configs

```python
import json
from platform_core.deploy_security import CyberGymFirewall, K8sAgentSandboxGenerator
from platform_core.layer1_intelligence import ModelRegistry, RadixPrefixCacheSimulator

# 1. Generate SGLang v0.5.19 launch commands for all 5 default pool models
registry = ModelRegistry()
serving_configs = RadixPrefixCacheSimulator.build_default_pool_configs(registry.all_models())
for cfg in serving_configs:
    print(f"[{cfg.model_id} (port {cfg.port})]: {' '.join(cfg.to_launch_args())}")

# 2. Generate Kubernetes agent-sandbox CRDs (SandboxTemplate + SandboxClaim)
k8s_gen = K8sAgentSandboxGenerator(namespace="ai-platform-sandboxes")
template_crd = k8s_gen.build_sandbox_template(
    template_name="firecracker-secverifier-template",
    vcpu_count=2,
    memory_mib=512,
    network_internal_only=True,
)
claim_crd = k8s_gen.build_sandbox_claim(
    claim_name="claim-session-01",
    template_name="firecracker-secverifier-template",
    session_id="session-01",
    tainted=True,
)
print("K8s SandboxTemplate Kind:", template_crd["kind"], "| Runtime:", template_crd["spec"]["runtimeClassName"])
print("K8s SandboxClaim Taint:", claim_crd["metadata"]["annotations"]["platform.ai/taint-state"])

# 3. Generate Squid Egress Proxy configuration
firewall = CyberGymFirewall()
print("\n--- squid.conf ---")
print(firewall.generate_squid_conf())
```

---

## 6. Expected Results

- Prints 5 deterministic `python3 -m sglang.launch_server` commands on ports `30000..30004` (`mxfp4` with `--tp-size 1` or `2` for 284B/397B MoE models; `fp8` with `--tp-size 1` for 27.8B and 7.5B models).
- Prints `K8s SandboxTemplate Kind: SandboxTemplate | Runtime: kata-fc` and `K8s SandboxClaim Taint: TAINTED_UNTRUSTED`.
- Prints the 9-line hardened `squid.conf` restricting outbound access to `allowed_domains`.

---

## 7. Common Errors and Troubleshooting

| Error | Cause | Resolution |
| :--- | :--- | :--- |
| `ValueError: Unsupported serving engine '...'` | Passing an engine other than `"sglang"` or `"vllm"` to `ServingEndpointConfig`. | Use `"sglang"` or `"vllm"`. |
| `ValueError: Framework 'torchtune' is prohibited` | Requesting `framework="torchtune"` in `DistributedTrainingSpecBuilder.build_spec()`. | Use `"auto"`, `"pytorch_fsdp2_dtensor"`, or `"deepspeed_zero3"`. |

---

## 8. Related Documentation

- [Integrations & Boundaries](../architecture/integrations.md)
- [Security Architecture & Governance](../security/README.md)
- [Custom Model Creation & Execution Guide](../CUSTOM_MODEL_GUIDE.md)
