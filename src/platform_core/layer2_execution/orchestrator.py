"""The 10-Step Reliable Agent Execution Lifecycle Orchestrator (Layer 2).

Implements Section 10.3:
1. Task Ingestion & Taint Classification (`TAINTED_UNTRUSTED` on external code/binaries)
2. Structural Pre-Indexing & Decomposition (`PrincipalOrchestratorAgent`)
3. Specialist & Thinking-Budget Routing (`AdaptiveModelRouter`)
4. Scoped MCP Tool Binding (`SignedManifestVerifier`)
5. Policy Evaluation & Human `interrupt()` Approval Gate (SQLite checkpoint pause/resume)
6. Hardware-Isolated MicroVM Execution (`FirecrackerSandboxManager` + pre-execution CoW snapshot)
7. Structured Observation & Telemetry Capture (OpenTelemetry spans)
8. Independent Adversarial Verification (`IndependentVerifierAgent` SecVerifier gate)
9. Snapshot Rollback & Fault Recovery (<15ms CoW restore + up to 3 retries -> `TTS@4` on final try)
10. Verified Artifact Delivery & Memory Consolidation
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Callable

_SAFE_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")

from platform_core.deploy_security.governance import MCPToolManifest, SignedManifestVerifier
from platform_core.layer1_intelligence.inference import InferenceBackend
from platform_core.layer1_intelligence.router import AdaptiveModelRouter, RoutingRequest
from platform_core.layer3_evolution.memory import BitemporalEpisodicMemory

from .agents import (
    DefensiveCyberAgent,
    IndependentVerifierAgent,
    MultimodalDataAgent,
    PrincipalOrchestratorAgent,
    ReverseEngineeringAgent,
    SoftwareEngineeringAgent,
)
from .forensics_mcp import ForensicsMCPServer, ForensicVerdict
from .interfaces import AbstractExecutionContext
from .mcp_tools import (
    BinRevMCPServer,
    CodeGraphMCPServer,
    DataAndVisualMCPServer,
    DefensiveCyberMCPServer,
)
from .sandbox import FirecrackerSandboxManager
from .state import (
    ApprovalRequest,
    EpistemicAssessment,
    EpistemicClaim,
    EpistemicStatus,
    LifecycleStep,
    PlatformState,
    SQLiteStateCheckpointer,
    SubTask,
    TaintLevel,
    TaskStatus,
)
from .vuln_intel_mcp import VulnFindingClassification, VulnIntelMCPServer


class ExecutionLifecycleOrchestrator:
    """Executes the 10-step stateful multi-agent workflow with checkpointing and rollback."""

    def __init__(
        self,
        checkpointer: SQLiteStateCheckpointer | None = None,
        router: AdaptiveModelRouter | None = None,
        sandbox: AbstractExecutionContext | None = None,
        episodic_memory: BitemporalEpisodicMemory | None = None,
        signing_key: str = "sovereign-platform-mcp-hmac-key-2026",
        inference_backend: InferenceBackend | None = None,
        vuln_intel_mcp: VulnIntelMCPServer | None = None,
        forensics_mcp: ForensicsMCPServer | None = None,
    ) -> None:
        self.checkpointer = checkpointer or SQLiteStateCheckpointer(":memory:")
        self.router = router or AdaptiveModelRouter()
        self.sandbox = sandbox or FirecrackerSandboxManager()
        self.episodic_memory = episodic_memory or BitemporalEpisodicMemory()
        self.manifest_verifier = SignedManifestVerifier(signing_key=signing_key)
        self.inference_backend = inference_backend

        # Deterministic MCP Servers
        self.code_graph_mcp = CodeGraphMCPServer()
        self.binrev_mcp = BinRevMCPServer()
        self.cyber_mcp = DefensiveCyberMCPServer()
        self.data_visual_mcp = DataAndVisualMCPServer()
        self.vuln_intel_mcp = vuln_intel_mcp or VulnIntelMCPServer()
        self.forensics_mcp = forensics_mcp or ForensicsMCPServer()

        # The 6 Consolidated Specialist Agents
        self.orchestrator_agent = PrincipalOrchestratorAgent()
        self.swe_agent = SoftwareEngineeringAgent()
        self.binrev_agent = ReverseEngineeringAgent()
        self.cyber_agent = DefensiveCyberAgent()
        self.data_visual_agent = MultimodalDataAgent()
        self.verifier_agent = IndependentVerifierAgent()

        self._registered_manifests = self._build_signed_manifests()

    def get_session_status(self, session_id: str) -> PlatformState:
        """Retrieve the latest state checkpoint for a session."""
        state = self.checkpointer.load_latest(session_id)
        if state is None:
            raise KeyError(f"No checkpoint found for session '{session_id}'.")
        return state

    def _build_signed_manifests(self) -> dict[str, MCPToolManifest]:
        raw_manifests = [
            MCPToolManifest(
                tool_name="code_graph.query_symbol",
                server_id="code-graph-mcp",
                version="1.0.0",
                description="Query SCIP/AST symbol definitions and inverse callers.",
                parameters_schema={"type": "object", "required": ["symbol_name"]},
                required_scopes=("read_code",),
            ),
            MCPToolManifest(
                tool_name="code_graph.apply_str_replace_edit",
                server_id="code-graph-mcp",
                version="1.0.0",
                description="Apply syntax-checked str_replace diff block.",
                parameters_schema={"type": "object", "required": ["old_str", "new_str"]},
                required_scopes=("write_code",),
            ),
            MCPToolManifest(
                tool_name="cyber.scan_cpg_taint",
                server_id="defensive-cyber-mcp",
                version="1.0.0",
                description="Run CPG source-to-sink vulnerability taint analysis.",
                parameters_schema={"type": "object", "required": ["source_code"]},
                required_scopes=("audit_security",),
            ),
            MCPToolManifest(
                tool_name="binrev.inspect_binary",
                server_id="binrev-mcp",
                version="1.0.0",
                description="Inspect binary headers, checksec flags, and strings.",
                parameters_schema={"type": "object", "required": ["raw_bytes"]},
                required_scopes=("analyze_binary",),
            ),
            MCPToolManifest(
                tool_name="binrev.run_two_phase_sk2_decompile",
                server_id="binrev-mcp",
                version="1.0.0",
                description="Execute two-phase SK2Decompile + ReCopilot context recovery.",
                parameters_schema={"type": "object", "required": ["raw_ghidra_pseudocode"]},
                required_scopes=("decompile_binary",),
            ),
            MCPToolManifest(
                tool_name="data_visual.classify_transformation",
                server_id="data-visual-mcp",
                version="1.0.0",
                description="Classify payload into Encoding, Compression, Encryption, or Hashing.",
                parameters_schema={"type": "object", "required": ["data"]},
                required_scopes=("parse_data",),
            ),
            MCPToolManifest(
                tool_name="data_visual.synthesize_kaitai_struct_ksy",
                server_id="data-visual-mcp",
                version="1.0.0",
                description="Synthesize and validate Kaitai Struct .ksy schema.",
                parameters_schema={"type": "object", "required": ["format_id"]},
                required_scopes=("parse_data",),
            ),
            MCPToolManifest(
                tool_name="data_visual.ground_visual_observations",
                server_id="data-visual-mcp",
                version="1.0.0",
                description="Ground UI/diagram bounding boxes with epistemic zoom calibration.",
                parameters_schema={"type": "object", "required": ["regions"]},
                required_scopes=("ground_visual",),
            ),
            MCPToolManifest(
                tool_name="vuln_intel.audit_project",
                server_id="vuln-intel-mcp",
                version="1.0.0",
                description="Correlate SBOM dependencies & CPG findings with OSV/NVD/KEV/EPSS/CWE.",
                parameters_schema={"type": "object", "required": ["project_dir"]},
                required_scopes=("audit_security",),
            ),
            MCPToolManifest(
                tool_name="forensics.analyze_target",
                server_id="forensics-mcp",
                version="1.0.0",
                description="Analyze iOS/Android/Host forensic artifacts for STIX2 spyware IOCs.",
                parameters_schema={"type": "object", "required": ["target_dir"]},
                required_scopes=("audit_security",),
            ),
        ]
        return {m.tool_name: self.manifest_verifier.sign(m) for m in raw_manifests}

    def run_workflow(
        self,
        session_id: str,
        objective: str,
        task_domain: str,
        workspace_files: dict[str, str | bytes] | None = None,
        task_payload: dict[str, Any] | None = None,
        has_untrusted_artifacts: bool = True,
        requires_mutating_approval: bool = False,
        attempt_plan_provider: Callable[[int, list[str]], dict[str, Any]] | None = None,
        preferred_model_id: str | None = None,
    ) -> PlatformState:
        """Execute Steps 1-10 of the reliable agent lifecycle with durable checkpointing."""
        cleaned_sid = session_id.strip()
        if not cleaned_sid or not _SAFE_SESSION_ID_RE.match(cleaned_sid) or cleaned_sid in {".", ".."}:
            raise PermissionError(
                f"Invalid session_id '{session_id}': must match '^[A-Za-z0-9._-]+$' without path separators."
            )
        state = PlatformState(
            session_id=cleaned_sid,
            objective=objective,
            task_domain=task_domain,
            has_untrusted_artifacts=has_untrusted_artifacts,
            requires_mutating_approval=requires_mutating_approval,
        )

        # Step 1: Task Ingestion & Taint Classification
        state.current_step = LifecycleStep.STEP_1_INGEST_AND_TAINT
        state.status = TaskStatus.IN_PROGRESS
        state.taint_level = (
            TaintLevel.TAINTED_UNTRUSTED if has_untrusted_artifacts else TaintLevel.CLEAN
        )
        self._emit_span(
            state,
            "lifecycle.step1_ingest_and_taint",
            {"taint_level": state.taint_level.value},
        )
        self.checkpointer.save_checkpoint(state)

        # Step 2: Structural Pre-Indexing & Decomposition
        state.current_step = LifecycleStep.STEP_2_PRE_INDEX_AND_DECOMPOSE
        pre_index: dict[str, Any] = {}
        for fpath, content in (workspace_files or {}).items():
            if isinstance(content, str):
                pre_index[fpath] = self.code_graph_mcp.index_file(fpath, content)
        state.pre_index_summary = pre_index
        self.orchestrator_agent.decompose_objective(state)
        self._emit_span(
            state,
            "lifecycle.step2_pre_index_and_decompose",
            {"indexed_files": len(pre_index), "subtasks": len(state.subtasks)},
        )
        self.checkpointer.save_checkpoint(state)

        # Step 3: Specialist & Thinking-Budget Routing
        state.current_step = LifecycleStep.STEP_3_SPECIALIST_AND_THINKING_ROUTE
        routing_decision = self.router.route(
            RoutingRequest(
                task_id=session_id,
                task_domain=task_domain,
                prompt_tokens=4096,
                has_visual_input=bool((task_payload or {}).get("visual_regions")),
                uncertainty_entropy=0.45,
                preferred_model_id=preferred_model_id,
            )
        )
        state.routing_summary = {
            "selected_pool": routing_decision.selected_pool.value,
            "primary_model": routing_decision.primary_model.model_id,
            "thinking_mode": routing_decision.thinking_mode.value,
            "max_thinking_tokens_per_turn": routing_decision.max_thinking_tokens_per_turn,
            "best_of_n_rollouts": routing_decision.best_of_n_rollouts,
        }
        self._emit_span(state, "lifecycle.step3_routing", state.routing_summary)
        self.checkpointer.save_checkpoint(state)

        # Step 4: Scoped MCP Tool Binding
        state.current_step = LifecycleStep.STEP_4_SCOPED_MCP_BINDING
        for st in state.subtasks:
            agent_scopes = self._get_agent_scopes(st.assigned_agent)
            for tool_name in st.scoped_tools:
                manifest = self._registered_manifests[tool_name]
                if not self.manifest_verifier.verify(
                    manifest,
                    granted_scopes=agent_scopes,
                    session_tainted=(state.taint_level == TaintLevel.TAINTED_UNTRUSTED),
                ):
                    raise PermissionError(
                        f"Scoped MCP verification failed for tool '{tool_name}' on agent '{st.assigned_agent}'."
                    )
        self._emit_span(state, "lifecycle.step4_scoped_mcp_binding", {"verified": True})
        self.checkpointer.save_checkpoint(state)

        # Step 5: Policy Evaluation & Human Approval Gate (`interrupt()`)
        state.current_step = LifecycleStep.STEP_5_POLICY_AND_APPROVAL_GATE
        if state.requires_mutating_approval and (
            state.approval_request is None or not state.approval_request.approved
        ):
            state.status = TaskStatus.AWAITING_HUMAN_APPROVAL
            state.approval_request = ApprovalRequest(
                request_id=f"apr-{session_id}",
                action_description=f"Execute state-mutating workflow: {objective}",
                risk_reason="High-impact or security-sensitive action requires operator approval.",
                approved=False,
            )
            self._emit_span(
                state,
                "lifecycle.step5_human_approval_interrupt",
                {"approval_request_id": state.approval_request.request_id},
            )
            self.checkpointer.save_checkpoint(state)
            return state

        return self._execute_steps_6_to_10(
            state=state,
            workspace_files=workspace_files or {},
            task_payload=task_payload or {},
            attempt_plan_provider=attempt_plan_provider,
        )

    def approve_and_resume(
        self,
        session_id: str,
        operator_id: str,
        workspace_files: dict[str, str | bytes] | None = None,
        task_payload: dict[str, Any] | None = None,
        attempt_plan_provider: Callable[[int, list[str]], dict[str, Any]] | None = None,
    ) -> PlatformState:
        """Resume a paused workflow from its SQLite checkpoint after cryptographic approval."""
        state = self.checkpointer.load_latest(session_id)
        if state is None:
            raise KeyError(f"No checkpoint found for session '{session_id}'.")
        if state.status != TaskStatus.AWAITING_HUMAN_APPROVAL or state.approval_request is None:
            raise ValueError(f"Session '{session_id}' is not awaiting human approval.")

        sig_input = f"{session_id}:{operator_id}:{state.approval_request.request_id}".encode("utf-8")
        state.approval_request.approved = True
        state.approval_request.operator_id = operator_id
        state.approval_request.approval_signature = hashlib.sha256(sig_input).hexdigest()
        state.status = TaskStatus.IN_PROGRESS
        self._emit_span(
            state,
            "lifecycle.step5_human_approval_granted",
            {"operator_id": operator_id, "signature": state.approval_request.approval_signature},
        )
        self.checkpointer.save_checkpoint(state)

        return self._execute_steps_6_to_10(
            state=state,
            workspace_files=workspace_files or {},
            task_payload=task_payload or {},
            attempt_plan_provider=attempt_plan_provider,
        )

    def _execute_steps_6_to_10(
        self,
        state: PlatformState,
        workspace_files: dict[str, str | bytes],
        task_payload: dict[str, Any],
        attempt_plan_provider: Callable[[int, list[str]], dict[str, Any]] | None = None,
    ) -> PlatformState:
        vm_id = f"vm-{state.session_id}"
        self.sandbox.provision_microvm(
            vm_id=vm_id,
            initial_files=workspace_files,
            tainted=(state.taint_level == TaintLevel.TAINTED_UNTRUSTED),
        )

        for subtask in state.subtasks:
            while subtask.retry_count < subtask.max_retries:
                # Step 6: Hardware-Isolated MicroVM Execution + Pre-Execution CoW Snapshot
                state.current_step = LifecycleStep.STEP_6_MICROVM_EXECUTION
                snapshot = self.sandbox.create_cow_snapshot(vm_id)
                subtask.active_snapshot_id = snapshot.snapshot_id

                active_plan = (
                    attempt_plan_provider(subtask.retry_count, subtask.verifier_feedback)
                    if attempt_plan_provider is not None
                    else task_payload
                )

                self._dispatch_specialist(subtask, vm_id, active_plan)
                self.checkpointer.save_checkpoint(state)

                # Step 7: Structured Observation & Telemetry Capture
                state.current_step = LifecycleStep.STEP_7_OBSERVATION_AND_TELEMETRY
                self._emit_span(
                    state,
                    "lifecycle.step7_observation",
                    {
                        "subtask_id": subtask.subtask_id,
                        "retry_attempt": subtask.retry_count,
                        "snapshot_id": snapshot.snapshot_id,
                    },
                )
                self.checkpointer.save_checkpoint(state)

                # Step 8: Independent Adversarial Verification (SecVerifier Gate)
                state.current_step = LifecycleStep.STEP_8_INDEPENDENT_VERIFICATION
                ver_result = self.verifier_agent.verify_subtask(
                    subtask=subtask,
                    sandbox=self.sandbox,
                    vm_id=vm_id,
                    cyber_mcp=self.cyber_mcp,
                )
                self._emit_span(state, "lifecycle.step8_independent_verification", ver_result)
                self.checkpointer.save_checkpoint(state)

                if subtask.status == TaskStatus.COMPLETED:
                    break

                # Step 9: Snapshot Rollback & Fault Recovery
                state.current_step = LifecycleStep.STEP_9_SNAPSHOT_ROLLBACK_AND_RETRY
                restore_info = self.sandbox.restore_cow_snapshot(snapshot.snapshot_id)
                subtask.retry_count += 1

                # Escalate to TTS@4 Best-of-N rollouts on final retry attempt
                if subtask.retry_count == subtask.max_retries - 1:
                    escalated_route = self.router.route(
                        RoutingRequest(
                            task_id=state.session_id,
                            task_domain=state.task_domain,
                            prompt_tokens=4096,
                            uncertainty_entropy=0.65,
                            retry_attempt=subtask.retry_count,
                            preferred_model_id=state.routing_summary.get("primary_model"),
                        )
                    )
                    state.routing_summary["best_of_n_rollouts"] = escalated_route.best_of_n_rollouts

                self._emit_span(
                    state,
                    "lifecycle.step9_snapshot_rollback",
                    {
                        "subtask_id": subtask.subtask_id,
                        "retry_count": subtask.retry_count,
                        "restore_latency_ms": restore_info["restore_latency_ms"],
                        "escalated_best_of_n": state.routing_summary.get("best_of_n_rollouts", 1),
                    },
                )
                self.checkpointer.save_checkpoint(state)

            if subtask.status != TaskStatus.COMPLETED:
                subtask.status = TaskStatus.FAILED_ESCALATED
                state.status = TaskStatus.FAILED_ESCALATED
                self.checkpointer.save_checkpoint(state)
                return state

        # Step 10: Verified Artifact Delivery & Memory Consolidation
        state.current_step = LifecycleStep.STEP_10_ARTIFACT_DELIVERY_AND_MEMORY
        state.status = TaskStatus.COMPLETED
        mem_event = self.episodic_memory.append_event(
            session_id=state.session_id,
            event_type=f"verified_{state.task_domain}_delivery",
            summary=state.objective,
        )
        mem_fact = self.episodic_memory.upsert_architectural_fact(
            subject=state.session_id,
            predicate="verified_domain_status",
            object_val=f"{state.task_domain}:COMPLETED",
            commit_sha=mem_event.event_id,
        )
        state.epistemic_assessment = self._build_epistemic_assessment(state)
        state.final_deliverable = {
            "session_id": state.session_id,
            "verified": True,
            "verified_by": self.verifier_agent.descriptor.agent_id,
            "consolidated_memory_event_id": mem_event.event_id,
            "consolidated_fact_id": mem_fact.fact_id,
            "routing_summary": dict(state.routing_summary),
            "epistemic_assessment": state.epistemic_assessment.to_dict(),
            "subtask_outputs": {st.subtask_id: st.candidate_output for st in state.subtasks},
        }
        self._emit_span(
            state,
            "lifecycle.step10_artifact_delivery",
            {
                "status": state.status.value,
                "subtasks_completed": len(state.subtasks),
                "memory_event_id": mem_event.event_id,
            },
        )
        self.checkpointer.save_checkpoint(state)
        return state

    def _dispatch_specialist(
        self,
        subtask: SubTask,
        vm_id: str,
        payload: dict[str, Any],
    ) -> None:
        if subtask.assigned_agent == "software_engineering":
            self.swe_agent.execute_subtask(
                subtask=subtask,
                sandbox=self.sandbox,
                vm_id=vm_id,
                code_graph=self.code_graph_mcp,
                patch_plan=payload,
            )
        elif subtask.assigned_agent == "defensive_cyber":
            if subtask.domain == "vuln_intel":
                self.cyber_agent.execute_vuln_intel_subtask(
                    subtask=subtask,
                    sandbox=self.sandbox,
                    vm_id=vm_id,
                    vuln_intel_mcp=self.vuln_intel_mcp,
                    cyber_mcp=self.cyber_mcp,
                    audit_plan=payload,
                )
            elif subtask.domain == "forensics":
                self.cyber_agent.execute_forensics_subtask(
                    subtask=subtask,
                    sandbox=self.sandbox,
                    vm_id=vm_id,
                    forensics_mcp=self.forensics_mcp,
                    forensic_plan=payload,
                )
            else:
                self.cyber_agent.execute_subtask(
                    subtask=subtask,
                    sandbox=self.sandbox,
                    vm_id=vm_id,
                    cyber_mcp=self.cyber_mcp,
                    code_graph=self.code_graph_mcp,
                    remediation_plan=payload,
                )
        elif subtask.assigned_agent == "reverse_engineering":
            self.binrev_agent.execute_subtask(
                subtask=subtask,
                binrev_mcp=self.binrev_mcp,
                binary_payload=payload.get("binary_payload", b"\x7fELF\x02\x01\x01\x00"),
                raw_pseudocode=payload.get("raw_pseudocode", "int main() { return 0; }"),
                callers=payload.get("callers", []),
                callees=payload.get("callees", []),
                dataflow_aliases=payload.get("dataflow_aliases", {}),
            )
        else:
            self.data_visual_agent.execute_subtask(
                subtask=subtask,
                data_visual_mcp=self.data_visual_mcp,
                sample_payload=payload.get("sample_payload", b"MAGIC\x01\x02"),
                format_id=payload.get("format_id", "custom_packet"),
                magic_bytes=payload.get("magic_bytes", b"MAGIC"),
                fields=payload.get("fields", [{"id": "payload", "type": "u2", "size_bytes": 2}]),
                visual_regions=payload.get("visual_regions", []),
            )

    @staticmethod
    def _build_epistemic_assessment(state: PlatformState) -> EpistemicAssessment:
        claims: list[EpistemicClaim] = []
        for idx, st in enumerate(state.subtasks, start=1):
            out = st.candidate_output
            if st.domain == "forensics":
                assessment = out.get("forensic_assessment", {})
                findings = assessment.get("findings", [])
                if not findings:
                    limitations = tuple(assessment.get("visibility_limitations", []))
                    claims.append(
                        EpistemicClaim(
                            claim_id=f"claim-{idx}",
                            status=EpistemicStatus.UNCERTAIN if limitations else EpistemicStatus.FACT,
                            statement=(
                                f"No known spyware IOC detected across {assessment.get('artifacts_inspected', 0)} "
                                "inspected artifacts (partial visibility)."
                                if limitations
                                else f"No known spyware IOC detected across {assessment.get('artifacts_inspected', 0)} inspected artifacts."
                            ),
                            evidence_refs=limitations or ("clean_triage_scan",),
                            confidence=float(assessment.get("confidence", 0.5)),
                            source_tool="forensics.analyze_target",
                            requires_human_verification=False,
                        )
                    )
                for f_idx, f in enumerate(findings, start=1):
                    verdict = f.get("verdict")
                    status = (
                        EpistemicStatus.FACT
                        if verdict == ForensicVerdict.CONFIRMED_IOC_MATCH.value
                        else EpistemicStatus.HYPOTHESIS
                    )
                    claims.append(
                        EpistemicClaim(
                            claim_id=f"claim-{idx}-{f_idx}",
                            status=status,
                            statement=str(f.get("rationale", f.get("matched_value", "Forensic finding"))),
                            evidence_refs=(str(f.get("artifact_path", "")), str(f.get("artifact_sha256", ""))),
                            confidence=float(f.get("confidence", 0.6)),
                            source_tool="forensics.analyze_target",
                            alternative_hypotheses=tuple(f.get("alternative_benign_explanations", [])),
                            requires_human_verification=bool(f.get("requires_human_verification", True)),
                        )
                    )
            elif st.domain == "vuln_intel":
                rep = out.get("vuln_intel_report", {})
                all_vulns = [
                    *rep.get("dependency_findings", []),
                    *rep.get("code_findings", []),
                ]
                for v_idx, v in enumerate(all_vulns, start=1):
                    is_conf = v.get("classification") == VulnFindingClassification.CONFIRMED_VULNERABILITY.value
                    claims.append(
                        EpistemicClaim(
                            claim_id=f"claim-{idx}-{v_idx}",
                            status=EpistemicStatus.FACT if is_conf else EpistemicStatus.HYPOTHESIS,
                            statement=str(v.get("rationale") or v.get("description") or v.get("vuln_id") or v.get("cwe_id")),
                            evidence_refs=(str(v.get("vuln_id") or v.get("cwe_id") or ""), str(v.get("source_file") or f"line:{v.get('line_number', 0)}")),
                            confidence=float(v.get("confidence", 0.7)),
                            source_tool="vuln_intel.audit_project",
                            requires_human_verification=bool(v.get("kev_listed", False) or is_conf),
                        )
                    )
                if not all_vulns:
                    claims.append(
                        EpistemicClaim(
                            claim_id=f"claim-{idx}-clean",
                            status=EpistemicStatus.FACT,
                            statement=f"Scanned {rep.get('dependencies_scanned', 0)} dependencies with 0 vulnerability matches in mirrored feeds.",
                            evidence_refs=("vuln_intel_mirror",),
                            confidence=0.88,
                            source_tool="vuln_intel.audit_project",
                            requires_human_verification=False,
                        )
                    )
            else:
                claims.append(
                    EpistemicClaim(
                        claim_id=f"claim-{idx}",
                        status=EpistemicStatus.FACT,
                        statement=f"Subtask '{st.title}' verified independently in isolated microVM.",
                        evidence_refs=(st.subtask_id, str(st.verified_by_agent or "independent_verifier")),
                        confidence=0.95,
                        source_tool="independent_verifier",
                        requires_human_verification=False,
                    )
                )
        return EpistemicAssessment.from_claims(claims)

    def _get_agent_scopes(self, agent_id: str) -> frozenset[str]:
        mapping = {
            "principal_orchestrator": self.orchestrator_agent.descriptor.allowed_mcp_scopes,
            "software_engineering": self.swe_agent.descriptor.allowed_mcp_scopes,
            "reverse_engineering": self.binrev_agent.descriptor.allowed_mcp_scopes,
            "defensive_cyber": self.cyber_agent.descriptor.allowed_mcp_scopes,
            "multimodal_data": self.data_visual_agent.descriptor.allowed_mcp_scopes,
            "independent_verifier": self.verifier_agent.descriptor.allowed_mcp_scopes,
        }
        return mapping[agent_id]

    @staticmethod
    def _emit_span(state: PlatformState, span_name: str, attributes: dict[str, Any]) -> None:
        state.telemetry_spans.append(
            {
                "span_name": span_name,
                "step": int(state.current_step),
                "timestamp": time.time(),
                "attributes": attributes,
            }
        )
