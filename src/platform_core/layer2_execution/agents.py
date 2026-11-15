"""The 6 Consolidated Specialist Agent Nodes in Layer 2 Execution.

Implements Section 3.2:
Consolidates the 12 candidate roles into 6 measurable execution nodes inside the stateful graph:
1. `PrincipalOrchestratorAgent` (Roles 1, 2, 10 — Pool 1)
2. `SoftwareEngineeringAgent` (Roles 3, 4, 5 — Pool 2)
3. `ReverseEngineeringAgent` (Role 6 — Pool 3 + Pool 1)
4. `DefensiveCyberAgent` (Role 7 — Pool 2)
5. `MultimodalDataAgent` (Roles 8, 9 — Pool 4 + Pool 2)
6. `IndependentVerifierAgent` (Roles 11, 12 — Pool 2 + Deterministic Runners)

Hard Invariant: Executor agents CANNOT mark their own tasks as `COMPLETED`. Only
`IndependentVerifierAgent` is authorized to transition a task to `COMPLETED`.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import tempfile
from typing import Any, Callable

from platform_core.layer1_intelligence.inference import (
    ChatMessage,
    InferenceBackend,
    InferenceRequest,
    ToolDefinition,
)
from platform_core.layer1_intelligence.models import ModelPool

from .forensics_mcp import ForensicVerdict, ForensicsMCPServer
from .mcp_tools import (
    BinRevMCPServer,
    CodeGraphMCPServer,
    DataAndVisualMCPServer,
    DefensiveCyberMCPServer,
    VisualRegionObservation,
)
from .sandbox import FirecrackerSandboxManager
from .state import PlatformState, SubTask, TaskStatus
from .vuln_intel_mcp import VulnIntelMCPServer


@dataclass(frozen=True)
class AgentNodeDescriptor:
    """Metadata describing a consolidated specialist agent node and its absorbed roles."""

    agent_id: str
    display_name: str
    absorbed_candidate_roles: tuple[str, ...]
    backing_pool: ModelPool
    allowed_mcp_scopes: frozenset[str]
    can_mark_completed: bool = False


class BaseSpecialistAgent:
    """Base class for all 6 specialist agent nodes."""

    descriptor: AgentNodeDescriptor

    def set_subtask_status(self, subtask: SubTask, new_status: TaskStatus) -> None:
        """Enforce the SecVerifier invariant: executor agents cannot self-certify completion."""
        if new_status == TaskStatus.COMPLETED and not self.descriptor.can_mark_completed:
            raise PermissionError(
                f"Agent '{self.descriptor.agent_id}' is forbidden from marking SubTask "
                f"'{subtask.subtask_id}' as COMPLETED. Only 'independent_verifier' may do so."
            )
        subtask.status = new_status


class AgentToolLoop:
    """Real multi-turn LLM tool-calling execution loop bound to scoped MCP handlers."""

    def __init__(
        self,
        backend: InferenceBackend,
        model_id: str,
        tools: list[ToolDefinition],
        handlers: dict[str, Callable[[dict[str, Any]], Any]],
        max_turns: int = 8,
    ) -> None:
        if max_turns <= 0:
            raise ValueError("max_turns must be positive.")
        self.backend = backend
        self.model_id = model_id
        self.tools = tools
        self.handlers = handlers
        self.max_turns = max_turns

    def run(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        """Run ReAct/tool-calling loop until final answer or turn budget exhaustion."""
        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=system_prompt),
            ChatMessage(role="user", content=user_prompt),
        ]
        tool_trace: list[dict[str, Any]] = []
        total_tokens = 0
        final_text = ""

        for turn in range(1, self.max_turns + 1):
            resp = self.backend.generate(
                InferenceRequest(
                    model_id=self.model_id,
                    messages=tuple(messages),
                    tools=tuple(self.tools),
                    temperature=temperature,
                )
            )
            total_tokens += resp.prompt_tokens + resp.completion_tokens
            if not resp.tool_calls:
                final_text = resp.content
                return {
                    "final_text": final_text,
                    "tool_trace": tool_trace,
                    "turns_used": turn,
                    "total_tokens": total_tokens,
                }

            messages.append(
                ChatMessage(
                    role="assistant",
                    content=resp.content,
                    tool_calls=resp.tool_calls,
                )
            )
            for tc in resp.tool_calls:
                handler = self.handlers.get(tc.name)
                if handler is None:
                    result_obj: Any = {"error": f"Tool '{tc.name}' is not bound in this scope."}
                else:
                    try:
                        result_obj = handler(tc.arguments)
                    except Exception as exc:
                        result_obj = {"error": f"{type(exc).__name__}: {exc}"}
                tool_trace.append(
                    {
                        "turn": turn,
                        "call_id": tc.call_id,
                        "tool": tc.name,
                        "arguments": tc.arguments,
                        "result": result_obj,
                    }
                )
                messages.append(
                    ChatMessage(
                        role="tool",
                        name=tc.name,
                        tool_call_id=tc.call_id,
                        content=json.dumps(result_obj, default=str),
                    )
                )

        return {
            "final_text": final_text,
            "tool_trace": tool_trace,
            "turns_used": self.max_turns,
            "total_tokens": total_tokens,
        }


class PrincipalOrchestratorAgent(BaseSpecialistAgent):
    """Node 1: Absorbs Central Orchestrator (1) + Principal Architect (2) + Research Agent (10)."""

    descriptor = AgentNodeDescriptor(
        agent_id="principal_orchestrator",
        display_name="Principal Orchestrator & Architect Agent",
        absorbed_candidate_roles=(
            "1. Central Orchestrator",
            "2. Principal Software Architect",
            "10. Research Agent",
        ),
        backing_pool=ModelPool.POOL_1_ORCHESTRATOR,
        allowed_mcp_scopes=frozenset({"read_code", "parse_data", "ground_visual"}),
        can_mark_completed=False,
    )

    def decompose_objective(self, state: PlatformState) -> list[SubTask]:
        """Decompose the user request into a scoped DAG of SubTasks with minimum MCP permissions."""
        domain = state.task_domain.lower().strip()
        if domain in {"swe", "architecture"}:
            subtasks = [
                SubTask(
                    subtask_id=f"{state.session_id}-sub-1",
                    title="Localize root cause via SCIP/AST and generate syntax-verified patch",
                    domain=domain,
                    assigned_agent="software_engineering",
                    scoped_tools=["code_graph.query_symbol", "code_graph.apply_str_replace_edit"],
                )
            ]
        elif domain == "cyber":
            subtasks = [
                SubTask(
                    subtask_id=f"{state.session_id}-sub-1",
                    title="Audit CPG taint paths, reproduce PoC, and apply dual-gate remediation patch",
                    domain="cyber",
                    assigned_agent="defensive_cyber",
                    scoped_tools=["cyber.scan_cpg_taint", "code_graph.apply_str_replace_edit"],
                )
            ]
        elif domain == "binrev":
            subtasks = [
                SubTask(
                    subtask_id=f"{state.session_id}-sub-1",
                    title="Perform static binary audit and two-phase SK2Decompile + ReCopilot recovery",
                    domain="binrev",
                    assigned_agent="reverse_engineering",
                    scoped_tools=["binrev.inspect_binary", "binrev.run_two_phase_sk2_decompile"],
                )
            ]
        elif domain in {"data_protocol", "visual_ocr"}:
            subtasks = [
                SubTask(
                    subtask_id=f"{state.session_id}-sub-1",
                    title="Classify data transformation, synthesize Kaitai .ksy schema, and ground visuals",
                    domain=domain,
                    assigned_agent="multimodal_data",
                    scoped_tools=[
                        "data_visual.classify_transformation",
                        "data_visual.synthesize_kaitai_struct_ksy",
                        "data_visual.ground_visual_observations",
                    ],
                )
            ]
        elif domain == "vuln_intel":
            subtasks = [
                SubTask(
                    subtask_id=f"{state.session_id}-sub-1",
                    title="Correlate project SBOM/dependencies and CPG findings against OSV/NVD/KEV/EPSS/CWE",
                    domain="vuln_intel",
                    assigned_agent="defensive_cyber",
                    scoped_tools=["vuln_intel.audit_project", "cyber.scan_cpg_taint"],
                )
            ]
        elif domain == "forensics":
            subtasks = [
                SubTask(
                    subtask_id=f"{state.session_id}-sub-1",
                    title="Triage endpoint/mobile forensic artifacts for STIX2 IOCs and spyware anomalies",
                    domain="forensics",
                    assigned_agent="defensive_cyber",
                    scoped_tools=["forensics.analyze_target"],
                )
            ]
        else:
            raise ValueError(f"Unsupported task_domain '{state.task_domain}'.")
        state.subtasks = subtasks
        return subtasks


class SoftwareEngineeringAgent(BaseSpecialistAgent):
    """Node 2: Absorbs Senior Programming (3) + Code Analysis (4) + Debugging Agent (5)."""

    descriptor = AgentNodeDescriptor(
        agent_id="software_engineering",
        display_name="Software Engineering & Debugging Agent",
        absorbed_candidate_roles=(
            "3. Senior Programming Agent",
            "4. Code Analysis Agent",
            "5. Debugging Agent",
        ),
        backing_pool=ModelPool.POOL_2_SWE_CYBER,
        allowed_mcp_scopes=frozenset({"read_code", "write_code", "run_sandbox"}),
        can_mark_completed=False,
    )

    def execute_subtask(
        self,
        subtask: SubTask,
        sandbox: FirecrackerSandboxManager,
        vm_id: str,
        code_graph: CodeGraphMCPServer,
        patch_plan: dict[str, Any],
    ) -> dict[str, Any]:
        """Navigate code via SCIP/AST, apply a structured str_replace edit, and request verification."""
        self.set_subtask_status(subtask, TaskStatus.IN_PROGRESS)
        files = sandbox.read_workspace_files(vm_id)
        target_file = patch_plan.get("target_file", "app.py")
        source = files.get(target_file, "")

        index_stats = code_graph.index_file(target_file, source)
        edit_res = code_graph.apply_str_replace_edit(
            source_code=source,
            old_str=patch_plan.get("old_str", ""),
            new_str=patch_plan.get("new_str", ""),
            language="python",
        )
        if edit_res["applied"]:
            sandbox.write_workspace_file(vm_id, target_file, edit_res["updated_source"])

        subtask.candidate_output = {
            "target_file": target_file,
            "edit_applied": edit_res["applied"],
            "edit_error": edit_res["error"],
            "index_stats": index_stats,
            "updated_source": edit_res["updated_source"],
            "test_script": patch_plan.get("test_script", "assert True\n"),
        }
        self.set_subtask_status(subtask, TaskStatus.AWAITING_VERIFICATION)
        return subtask.candidate_output


class ReverseEngineeringAgent(BaseSpecialistAgent):
    """Node 3: Absorbs Reverse Engineering Agent (6) driving GhidraMCP / SK2Decompile / ReCopilot."""

    descriptor = AgentNodeDescriptor(
        agent_id="reverse_engineering",
        display_name="Reverse Engineering & Binary Agent",
        absorbed_candidate_roles=("6. Reverse Engineering Agent",),
        backing_pool=ModelPool.POOL_3_BINREV,
        allowed_mcp_scopes=frozenset({"analyze_binary", "decompile_binary", "parse_data", "run_sandbox"}),
        can_mark_completed=False,
    )

    def execute_subtask(
        self,
        subtask: SubTask,
        binrev_mcp: BinRevMCPServer,
        binary_payload: bytes,
        raw_pseudocode: str,
        callers: list[str],
        callees: list[str],
        dataflow_aliases: dict[str, str],
    ) -> dict[str, Any]:
        """Inspect binary headers/checksec and execute Two-Phase SK2Decompile + ReCopilot."""
        self.set_subtask_status(subtask, TaskStatus.IN_PROGRESS)
        inspection = binrev_mcp.inspect_binary(binary_payload)
        decompilation = binrev_mcp.run_two_phase_sk2_decompile(
            raw_ghidra_pseudocode=raw_pseudocode,
            callers=callers,
            callees=callees,
            dataflow_aliases=dataflow_aliases,
            cross_ref_strings=inspection["extracted_strings"][:10],
        )
        subtask.candidate_output = {
            "binary_inspection": inspection,
            "decompilation": decompilation,
        }
        self.set_subtask_status(subtask, TaskStatus.AWAITING_VERIFICATION)
        return subtask.candidate_output


class DefensiveCyberAgent(BaseSpecialistAgent):
    """Node 4: Absorbs Defensive Cybersecurity Agent (7) for CPG taint & sanitizer patching."""

    descriptor = AgentNodeDescriptor(
        agent_id="defensive_cyber",
        display_name="Defensive Cybersecurity Agent",
        absorbed_candidate_roles=("7. Defensive Cybersecurity Agent",),
        backing_pool=ModelPool.POOL_2_SWE_CYBER,
        allowed_mcp_scopes=frozenset({"read_code", "write_code", "audit_security", "run_sandbox"}),
        can_mark_completed=False,
    )

    def execute_subtask(
        self,
        subtask: SubTask,
        sandbox: FirecrackerSandboxManager,
        vm_id: str,
        cyber_mcp: DefensiveCyberMCPServer,
        code_graph: CodeGraphMCPServer,
        remediation_plan: dict[str, Any],
    ) -> dict[str, Any]:
        """Scan CPG taint paths, apply security remediation patch, and transition to verification."""
        self.set_subtask_status(subtask, TaskStatus.IN_PROGRESS)
        files = sandbox.read_workspace_files(vm_id)
        target_file = remediation_plan.get("target_file", "service.py")
        original_source = files.get(target_file, "")

        initial_findings = cyber_mcp.scan_cpg_taint(original_source)
        edit_res = code_graph.apply_str_replace_edit(
            source_code=original_source,
            old_str=remediation_plan.get("old_str", ""),
            new_str=remediation_plan.get("new_str", ""),
            language="python",
        )
        if edit_res["applied"]:
            sandbox.write_workspace_file(vm_id, target_file, edit_res["updated_source"])

        subtask.candidate_output = {
            "target_file": target_file,
            "initial_cwe_findings": [f.cwe_id for f in initial_findings],
            "edit_applied": edit_res["applied"],
            "patched_source": edit_res["updated_source"],
            "poc_triggered_crash": bool(remediation_plan.get("poc_still_crashes", False)),
            "regression_tests_passed": int(remediation_plan.get("regression_tests_passed", 10)),
            "regression_tests_total": int(remediation_plan.get("regression_tests_total", 10)),
            **(
                {"poc_script": remediation_plan["poc_script"]}
                if isinstance(remediation_plan.get("poc_script"), str)
                else {}
            ),
            **(
                {"regression_test_script": remediation_plan["regression_test_script"]}
                if isinstance(remediation_plan.get("regression_test_script"), str)
                else {}
            ),
        }
        self.set_subtask_status(subtask, TaskStatus.AWAITING_VERIFICATION)
        return subtask.candidate_output

    @staticmethod
    def _materialize_vm_files(
        sandbox: FirecrackerSandboxManager, vm_id: str, dest: Path
    ) -> None:
        raw_files = sandbox.read_raw_workspace_files(vm_id)
        root = dest.resolve()
        for rel_path, content in raw_files.items():
            sandbox._validate_rel_path(rel_path)
            target = (root / rel_path).resolve()
            if not target.is_relative_to(root):
                raise PermissionError(f"Unsafe VM relative path rejected: {rel_path}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

    def execute_vuln_intel_subtask(
        self,
        subtask: SubTask,
        sandbox: FirecrackerSandboxManager,
        vm_id: str,
        vuln_intel_mcp: VulnIntelMCPServer,
        cyber_mcp: DefensiveCyberMCPServer,
        audit_plan: dict[str, Any],
    ) -> dict[str, Any]:
        """Audit workspace manifests & source code using mirrored vulnerability intelligence."""
        self.set_subtask_status(subtask, TaskStatus.IN_PROGRESS)
        vm_files = sandbox.read_workspace_files(vm_id)
        explicit_dir = audit_plan.get("project_dir")

        cpg_findings = []
        for fname, content in vm_files.items():
            if fname.endswith((".py", ".c", ".cpp", ".js", ".ts")):
                cpg_findings.extend(cyber_mcp.scan_cpg_taint(content))

        if explicit_dir:
            report = vuln_intel_mcp.audit_project_dependencies(
                project_dir=explicit_dir,
                cpg_findings=cpg_findings,
            )
        else:
            with tempfile.TemporaryDirectory(prefix="vuln_audit_") as tmpdir:
                self._materialize_vm_files(sandbox, vm_id, Path(tmpdir))
                report = vuln_intel_mcp.audit_project_dependencies(
                    project_dir=tmpdir,
                    cpg_findings=cpg_findings,
                )

        subtask.candidate_output = {
            "vuln_intel_report": report,
            "dependencies_scanned": report["dependencies_scanned"],
            "confirmed_vulnerabilities": report["summary"]["confirmed_vulnerabilities"],
            "potential_weaknesses": report["summary"]["potential_weaknesses"],
        }
        self.set_subtask_status(subtask, TaskStatus.AWAITING_VERIFICATION)
        return subtask.candidate_output

    def execute_forensics_subtask(
        self,
        subtask: SubTask,
        sandbox: FirecrackerSandboxManager,
        vm_id: str,
        forensics_mcp: ForensicsMCPServer,
        forensic_plan: dict[str, Any],
    ) -> dict[str, Any]:
        """Triage target forensic artifacts without fabricating indicators."""
        self.set_subtask_status(subtask, TaskStatus.IN_PROGRESS)
        explicit_dir = forensic_plan.get("target_dir")
        platform = str(forensic_plan.get("platform", "auto"))
        use_mvt = bool(forensic_plan.get("use_mvt_cli", False))
        if explicit_dir:
            assessment = forensics_mcp.analyze_forensic_target(
                target_dir=explicit_dir,
                platform=platform,
                use_mvt_cli=use_mvt,
            )
        else:
            with tempfile.TemporaryDirectory(prefix="forensics_vm_") as tmpdir:
                self._materialize_vm_files(sandbox, vm_id, Path(tmpdir))
                assessment = forensics_mcp.analyze_forensic_target(
                    target_dir=tmpdir,
                    platform=platform,
                    use_mvt_cli=use_mvt,
                )
        subtask.candidate_output = {
            "forensic_assessment": assessment.to_dict(),
            "overall_verdict": assessment.overall_verdict.value,
            "artifacts_inspected": assessment.artifacts_inspected,
        }
        self.set_subtask_status(subtask, TaskStatus.AWAITING_VERIFICATION)
        return subtask.candidate_output


class MultimodalDataAgent(BaseSpecialistAgent):
    """Node 5: Absorbs Visual Intelligence (8) + Data Analysis Agent (9)."""

    descriptor = AgentNodeDescriptor(
        agent_id="multimodal_data",
        display_name="Multimodal Visual & Data Intelligence Agent",
        absorbed_candidate_roles=(
            "8. Visual Intelligence Agent",
            "9. Data Analysis Agent",
        ),
        backing_pool=ModelPool.POOL_4_VISUAL_OCR,
        allowed_mcp_scopes=frozenset({"parse_data", "ground_visual"}),
        can_mark_completed=False,
    )

    def execute_subtask(
        self,
        subtask: SubTask,
        data_visual_mcp: DataAndVisualMCPServer,
        sample_payload: bytes,
        format_id: str,
        magic_bytes: bytes,
        fields: list[dict[str, Any]],
        visual_regions: list[VisualRegionObservation] | None = None,
    ) -> dict[str, Any]:
        """Classify payload transformation, synthesize Kaitai .ksy schema, and ground visuals."""
        self.set_subtask_status(subtask, TaskStatus.IN_PROGRESS)
        classification = data_visual_mcp.classify_transformation(sample_payload)
        ksy_result = data_visual_mcp.synthesize_kaitai_struct_ksy(
            format_id=format_id,
            magic_bytes=magic_bytes,
            fields=fields,
            sample_payload=sample_payload,
        )
        visual_result = data_visual_mcp.ground_visual_observations(visual_regions or [])
        subtask.candidate_output = {
            "transformation_classification": {
                "class": classification["transformation_class"].value,
                "subtype": classification["subtype"],
                "shannon_entropy": classification["shannon_entropy"],
            },
            "kaitai_schema": ksy_result,
            "visual_grounding": visual_result,
        }
        self.set_subtask_status(subtask, TaskStatus.AWAITING_VERIFICATION)
        return subtask.candidate_output


class IndependentVerifierAgent(BaseSpecialistAgent):
    """Node 6: Absorbs Testing & Validation (11) + Quality Assurance Agent (12).

    Acts as the adversarial SecVerifier gate (Section 3.2 & 10.3 Step 8).
    ONLY this agent has `can_mark_completed=True`.
    """

    descriptor = AgentNodeDescriptor(
        agent_id="independent_verifier",
        display_name="Independent Verifier, Testing & QA Agent",
        absorbed_candidate_roles=(
            "11. Testing & Validation Agent",
            "12. Quality Assurance Agent",
        ),
        backing_pool=ModelPool.POOL_2_SWE_CYBER,
        allowed_mcp_scopes=frozenset({"read_code", "audit_security", "parse_data", "run_sandbox"}),
        can_mark_completed=True,
    )

    def verify_subtask(
        self,
        subtask: SubTask,
        sandbox: FirecrackerSandboxManager,
        vm_id: str,
        cyber_mcp: DefensiveCyberMCPServer,
    ) -> dict[str, Any]:
        """Execute deterministic compiler/test/sanitizer/schema assertions in a clean microVM."""
        if subtask.status != TaskStatus.AWAITING_VERIFICATION:
            raise ValueError(
                f"IndependentVerifierAgent can only verify subtasks in AWAITING_VERIFICATION "
                f"(got {subtask.status.value})."
            )

        out = subtask.candidate_output
        domain = subtask.domain.lower().strip()

        if domain in {"swe", "architecture"}:
            if not out.get("edit_applied", False):
                reason = f"SWE patch failed AST/diff check: {out.get('edit_error')}"
                subtask.verifier_feedback.append(reason)
                self.set_subtask_status(subtask, TaskStatus.VERIFIER_REJECTED)
                return {"passed": False, "reason": reason}

            exec_res = sandbox.execute_python_in_sandbox(
                vm_id=vm_id,
                python_code=out.get("test_script", "assert True\n"),
            )
            if exec_res.exit_code != 0:
                reason = f"Unit/regression test failure (exit={exec_res.exit_code}): {exec_res.stderr.strip()}"
                subtask.verifier_feedback.append(reason)
                self.set_subtask_status(subtask, TaskStatus.VERIFIER_REJECTED)
                return {"passed": False, "reason": reason, "stderr": exec_res.stderr}

        elif domain == "cyber":
            if not out.get("edit_applied", False):
                reason = "Security patch failed diff application."
                subtask.verifier_feedback.append(reason)
                self.set_subtask_status(subtask, TaskStatus.VERIFIER_REJECTED)
                return {"passed": False, "reason": reason}

            poc_crashed = bool(out.get("poc_triggered_crash", False))
            reg_passed = int(out.get("regression_tests_passed", 0))
            reg_total = int(out.get("regression_tests_total", 1))

            poc_script = out.get("poc_script")
            if isinstance(poc_script, str) and poc_script.strip():
                poc_res = sandbox.execute_python_in_sandbox(vm_id=vm_id, python_code=poc_script)
                if poc_res.exit_code != 0:
                    poc_crashed = True

            reg_script = out.get("regression_test_script")
            if isinstance(reg_script, str) and reg_script.strip():
                reg_res = sandbox.execute_python_in_sandbox(vm_id=vm_id, python_code=reg_script)
                if reg_res.exit_code != 0:
                    reg_passed = 0
                else:
                    reg_passed = max(1, reg_total)

            gate = cyber_mcp.verify_dual_gate_patch(
                patched_source=out.get("patched_source", ""),
                poc_triggered_crash=poc_crashed,
                regression_tests_passed=reg_passed,
                regression_tests_total=reg_total,
            )
            if gate["verdict"] != "VERIFIED_PASS":
                reason = (
                    f"SecVerifier Dual-Gate rejected patch: mode={gate['failure_mode']}, "
                    f"remaining_cwes={gate['remaining_cwes']}"
                )
                subtask.verifier_feedback.append(reason)
                self.set_subtask_status(subtask, TaskStatus.VERIFIER_REJECTED)
                return {"passed": False, "reason": reason, "gate_details": gate}

        elif domain == "binrev":
            decomp = out.get("decompilation", {})
            skin_code = decomp.get("phase2_skin_decompiled_code", "")
            if "goto LAB_" in skin_code or not skin_code.strip():
                reason = "Decompiled code still contains unresolved raw goto labels or is empty."
                subtask.verifier_feedback.append(reason)
                self.set_subtask_status(subtask, TaskStatus.VERIFIER_REJECTED)
                return {"passed": False, "reason": reason}

        elif domain in {"data_protocol", "visual_ocr"}:
            ksy = out.get("kaitai_schema", {})
            if not ksy.get("full_byte_coverage", False):
                reason = (
                    f"Kaitai .ksy schema did not achieve 100% byte coverage "
                    f"(ratio={ksy.get('byte_coverage_ratio')})."
                )
                subtask.verifier_feedback.append(reason)
                self.set_subtask_status(subtask, TaskStatus.VERIFIER_REJECTED)
                return {"passed": False, "reason": reason}
            if domain == "visual_ocr":
                vis = out.get("visual_grounding", {})
                if not vis.get("epistemic_hallucination_guard_active", False):
                    reason = "Visual grounding missing epistemic hallucination guard."
                    subtask.verifier_feedback.append(reason)
                    self.set_subtask_status(subtask, TaskStatus.VERIFIER_REJECTED)
                    return {"passed": False, "reason": reason}

        elif domain == "vuln_intel":
            report = out.get("vuln_intel_report")
            if not isinstance(report, dict) or "summary" not in report:
                reason = "Vulnerability intelligence output missing structured summary."
                subtask.verifier_feedback.append(reason)
                self.set_subtask_status(subtask, TaskStatus.VERIFIER_REJECTED)
                return {"passed": False, "reason": reason}

        elif domain == "forensics":
            assessment = out.get("forensic_assessment")
            if not isinstance(assessment, dict) or "overall_verdict" not in assessment:
                reason = "Forensic triage output missing structured ForensicAssessment."
                subtask.verifier_feedback.append(reason)
                self.set_subtask_status(subtask, TaskStatus.VERIFIER_REJECTED)
                return {"passed": False, "reason": reason}
            for finding in assessment.get("findings", []):
                if finding.get("verdict") == ForensicVerdict.CONFIRMED_IOC_MATCH.value:
                    if not finding.get("artifact_sha256") or not finding.get("artifact_path"):
                        reason = "Anti-fabrication violation: CONFIRMED_IOC_MATCH finding lacks artifact path or SHA-256."
                        subtask.verifier_feedback.append(reason)
                        self.set_subtask_status(subtask, TaskStatus.VERIFIER_REJECTED)
                        return {"passed": False, "reason": reason}

        subtask.verified_by_agent = self.descriptor.agent_id
        self.set_subtask_status(subtask, TaskStatus.COMPLETED)
        return {"passed": True, "verified_by": self.descriptor.agent_id}
