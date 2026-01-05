"""Real-time detection module for SecureAgent."""

try:
    from secureagent.detectors.cloudtrail import CloudTrailDetector
except ImportError:
    CloudTrailDetector = None

__all__ = ["CloudTrailDetector"]
