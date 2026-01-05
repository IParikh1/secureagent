"""SARIF reporter for SecureAgent.

SARIF (Static Analysis Results Interchange Format) is a standard format
for static analysis tools, supported by GitHub Code Scanning and other platforms.
"""

import json
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path

from ..models.finding import Finding
from ..models.severity import Severity


def _get_severity_enum(severity) -> Severity:
    """Get Severity enum from severity, handling both enum and string."""
    if isinstance(severity, Severity):
        return severity
    return Severity(severity)


class SARIFReporter:
    """SARIF 2.1.0 output for scan results."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    # Map severity to SARIF levels
    SEVERITY_TO_LEVEL = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    # Map severity to SARIF security-severity scores
    SEVERITY_TO_SCORE = {
        Severity.CRITICAL: "9.0",
        Severity.HIGH: "7.0",
        Severity.MEDIUM: "4.0",
        Severity.LOW: "2.0",
        Severity.INFO: "0.0",
    }

    def __init__(self, tool_version: str = "1.0.0"):
        """Initialize SARIF reporter."""
        self.tool_version = tool_version

    def report(
        self,
        findings: List[Finding],
        scan_target: str = "",
        scan_duration: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate SARIF report."""
        sarif_report = self._build_sarif(findings, scan_target, metadata)
        return json.dumps(sarif_report, indent=2)

    def _build_sarif(
        self,
        findings: List[Finding],
        scan_target: str,
        metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build SARIF document."""
        # Collect unique rules
        rules = self._build_rules(findings)

        # Build results
        results = self._build_results(findings)

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecureAgent",
                            "version": self.tool_version,
                            "informationUri": "https://github.com/secureagent/secureagent",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                        }
                    ],
                    "artifacts": self._build_artifacts(findings, scan_target),
                }
            ],
        }

    def _build_rules(self, findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """Build SARIF rules from findings."""
        rules = {}

        for finding in findings:
            if finding.rule_id not in rules:
                rule = {
                    "id": finding.rule_id,
                    "name": finding.rule_id,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {
                        "level": self.SEVERITY_TO_LEVEL.get(_get_severity_enum(finding.severity), "note")
                    },
                    "properties": {
                        "security-severity": self.SEVERITY_TO_SCORE.get(
                            _get_severity_enum(finding.severity), "0.0"
                        ),
                        "tags": self._get_rule_tags(finding),
                    },
                }

                # Add help text if remediation available
                if finding.remediation:
                    rule["help"] = {
                        "text": finding.remediation,
                        "markdown": f"**Remediation:**\n\n{finding.remediation}",
                    }

                rules[finding.rule_id] = rule

        return rules

    def _build_results(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build SARIF results from findings."""
        results = []

        for finding in findings:
            result = {
                "ruleId": finding.rule_id,
                "level": self.SEVERITY_TO_LEVEL.get(_get_severity_enum(finding.severity), "note"),
                "message": {
                    "text": finding.description,
                },
                "locations": self._build_locations(finding),
            }

            # Add fingerprints
            result["fingerprints"] = {"primaryLocationLineHash": finding.id}

            # Add partial fingerprints for deduplication
            result["partialFingerprints"] = {
                "ruleId": finding.rule_id,
            }

            # Add related locations if available
            if finding.metadata and "related_locations" in finding.metadata:
                result["relatedLocations"] = finding.metadata["related_locations"]

            # Add code flows if available
            if finding.metadata and "code_flow" in finding.metadata:
                result["codeFlows"] = finding.metadata["code_flow"]

            results.append(result)

        return results

    def _build_locations(self, finding: Finding) -> List[Dict[str, Any]]:
        """Build SARIF locations from finding."""
        locations = []

        if finding.location:
            loc = finding.location
            location = {}

            if loc.file_path:
                physical_location = {
                    "artifactLocation": {
                        "uri": loc.file_path,
                        "uriBaseId": "%SRCROOT%",
                    }
                }

                if loc.line_number:
                    physical_location["region"] = {
                        "startLine": loc.line_number,
                    }
                    if loc.column:
                        physical_location["region"]["startColumn"] = loc.column

                location["physicalLocation"] = physical_location

            elif loc.resource_type and loc.resource_id:
                # Cloud resource location
                location["logicalLocations"] = [
                    {
                        "name": loc.resource_id,
                        "kind": loc.resource_type,
                        "fullyQualifiedName": f"{loc.resource_type}/{loc.resource_id}",
                    }
                ]

            if location:
                locations.append(location)

        return locations if locations else [{}]

    def _build_artifacts(
        self, findings: List[Finding], scan_target: str
    ) -> List[Dict[str, Any]]:
        """Build SARIF artifacts (files scanned)."""
        artifacts = []
        seen_paths = set()

        for finding in findings:
            if finding.location and finding.location.file_path:
                path = finding.location.file_path
                if path not in seen_paths:
                    seen_paths.add(path)
                    artifacts.append(
                        {
                            "location": {
                                "uri": path,
                                "uriBaseId": "%SRCROOT%",
                            }
                        }
                    )

        return artifacts

    def _get_rule_tags(self, finding: Finding) -> List[str]:
        """Get tags for a rule."""
        tags = ["security"]

        if finding.domain:
            domain_value = finding.domain.value if hasattr(finding.domain, 'value') else str(finding.domain)
            tags.append(domain_value)

        if finding.cwe_id:
            tags.append(f"external/cwe/{finding.cwe_id}")

        if finding.owasp_id:
            tags.append(f"external/owasp/{finding.owasp_id}")

        severity_tags = {
            Severity.CRITICAL: "security/critical",
            Severity.HIGH: "security/high",
            Severity.MEDIUM: "security/medium",
            Severity.LOW: "security/low",
        }
        severity_enum = _get_severity_enum(finding.severity)
        if severity_enum in severity_tags:
            tags.append(severity_tags[severity_enum])

        return tags

    def save(
        self,
        findings: List[Finding],
        output_path: Path,
        scan_target: str = "",
        scan_duration: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Save SARIF report to file."""
        report = self.report(findings, scan_target, scan_duration, metadata)
        output_path = Path(output_path)
        output_path.write_text(report)
