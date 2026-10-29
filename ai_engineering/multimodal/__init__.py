"""Multimodal Orchestration Package."""
from ai_engineering.multimodal.contracts import (
    InputType,
    MultimodalStatus,
    ExtractedIndicator,
    MultimodalExtractionResult,
    MultimodalAnalysisReport,
)
__all__ = [
    "InputType",
    "MultimodalStatus",
    "ExtractedIndicator",
    "MultimodalExtractionResult",
    "MultimodalAnalysisReport",
    "MultimodalOrchestrator",
]


def __getattr__(name: str):
    if name == "MultimodalOrchestrator":
        from ai_engineering.multimodal.multimodal_orchestrator import MultimodalOrchestrator
        return MultimodalOrchestrator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
