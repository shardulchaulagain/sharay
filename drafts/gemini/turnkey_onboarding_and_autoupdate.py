"""Turnkey First-Run Onboarding, Telemetry-Free Auto-Update & Adapter SDK.

Re-exports core onboarding implementations from aegis.onboarding.
"""

from aegis.onboarding import (
    BaseScannerAdapter,
    OnboardingState,
    OnboardingStep,
    OnboardingWizardEngine,
    PerformanceBudgetEnforcer,
    ReleaseManifest,
    ZeroTelemetryUpdateManager,
    onboarding_wizard,
)

__all__ = [
    "BaseScannerAdapter",
    "OnboardingState",
    "OnboardingStep",
    "OnboardingWizardEngine",
    "PerformanceBudgetEnforcer",
    "ReleaseManifest",
    "ZeroTelemetryUpdateManager",
    "onboarding_wizard",
]
