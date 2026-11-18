"""Layer 3: Evolution, Bitemporal Memory, Proprietary Data Factories, and PropBench-9."""

import importlib

# Preload Layer 1 models before `.evaluation` to break the pre-existing
# `evaluation -> layer1_intelligence.models -> training -> evaluation` cycle
# when `platform_core.layer3_evolution` is imported first.
importlib.import_module("platform_core.layer1_intelligence.models")

from .corpus_harvester import (
    CorpusHarvesterPipeline,
    DomainChunker,
    HarvestReport,
    HarvestedDocument,
    PDFBookExtractor,
    PromptInjectionSanitizer,
    RateLimitError,
    RateLimitedWebHarvester,
    TeacherDistiller,
)
from platform_core.data_ingestion.data_factory import (
    DatasetHygienePipeline,
    DecompileBenchFactory,
    SecBenchFactory,
    SWEFuseFactory,
    TrainingTrajectoryRecord,
)
from .evaluation import (
    BenchmarkCaseResult,
    BenchmarkEvaluator,
    BenchmarkSuiteRunner,
    MultiRunBenchmarkResult,
    PropBench9Suite,
    PropBenchSpec,
)
from .memory import (
    BitemporalEpisodicMemory,
    BitemporalFactEdge,
    DeterministicHashEmbedder,
    EmbeddingProvider,
    HybridKnowledgeStore,
    InferenceBackendEmbedder,
    KnowledgeDocumentChunk,
    ProgressionEvent,
    ProjectContextManager,
)
from .observability import (
    ControlledImprovementCycle,
    FailureRootCauseBucket,
    ProductionTraceRecord,
    TraceOutcome,
)

__all__ = [
    "BenchmarkCaseResult",
    "BenchmarkEvaluator",
    "BenchmarkSuiteRunner",
    "BitemporalEpisodicMemory",
    "BitemporalFactEdge",
    "ControlledImprovementCycle",
    "CorpusHarvesterPipeline",
    "DatasetHygienePipeline",
    "DecompileBenchFactory",
    "DeterministicHashEmbedder",
    "DomainChunker",
    "EmbeddingProvider",
    "FailureRootCauseBucket",
    "HarvestReport",
    "HarvestedDocument",
    "HybridKnowledgeStore",
    "InferenceBackendEmbedder",
    "KnowledgeDocumentChunk",
    "MultiRunBenchmarkResult",
    "PDFBookExtractor",
    "ProductionTraceRecord",
    "ProgressionEvent",
    "ProjectContextManager",
    "PromptInjectionSanitizer",
    "PropBench9Suite",
    "PropBenchSpec",
    "RateLimitError",
    "RateLimitedWebHarvester",
    "SWEFuseFactory",
    "SecBenchFactory",
    "TeacherDistiller",
    "TraceOutcome",
    "TrainingTrajectoryRecord",
]
