# SecureAgent ML Pipeline Fixes - Product Requirements Document

**Created:** 2026-03-02
**Last Updated:** 2026-03-02
**Status:** In Progress

## Overview

Fix the SecureAgent ML pipeline so that the shipped model, feature extractors, training pipeline, and CLI all work together correctly. The ML system must produce meaningful, non-zero risk scores that correlate with finding severity.

## Goals

1. Wire the `--risk-score` CLI flag into the scan pipeline (currently dead code)
2. Retrain the shipped model with current feature extractors (feature schema mismatch)
3. Fix model metadata to reflect binary classification (not 5-class)
4. Add synthetic data templates for all 9 scanner domains (only 3 covered)
5. Fix cross-validation to use actual ensemble model architecture
6. Fix hyperparameter tuning to tune actual ensemble
7. Implement retraining strategies or remove false claims
8. Unify the two risk-scoring paths

## Requirements

### Functional Requirements

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-1 | `--risk-score` flag produces ML risk scores in scan output | P0 | Pending |
| FR-2 | Shipped model features match CompositeFeatureExtractor output | P0 | Pending |
| FR-3 | model_metadata.json accurately describes binary classification | P0 | Pending |
| FR-4 | Synthetic data covers all 9 scanner domains | P1 | Pending |
| FR-5 | Cross-validation uses actual 3-model ensemble | P1 | Pending |
| FR-6 | Hyperparameter tuning tunes actual ensemble models | P1 | Pending |
| FR-7 | Retraining strategies implemented or claims removed | P2 | Pending |
| FR-8 | RiskScorer and RiskAnalyzer can be used together | P2 | Pending |

### Non-Functional Requirements

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| NFR-1 | All existing 308 tests continue to pass | High | Pending |
| NFR-2 | CRITICAL findings score > 0.7, INFO < 0.3 | High | Pending |
| NFR-3 | New tests added for all fixes | High | Pending |

## Technical Specifications

### Tech Stack
- Python 3.x with Pydantic models
- scikit-learn (RandomForest, GradientBoosting, LogisticRegression ensemble)
- Rich for CLI output
- Typer for CLI framework

### Execution Order
```
Fix 4 (templates) -> Fix 2 (retrain) -> Fix 3 (metadata) -> Fix 1 (wire CLI)
                                                               -> Fix 5 (CV)
                                                               -> Fix 6 (tune)
                                                               -> Fix 7 (strategies)
                                                               -> Fix 8 (unify)
```

## Success Criteria

- [ ] `secureagent scan <target> --risk-score` produces meaningful risk scores
- [ ] Shipped model feature schema matches CompositeFeatureExtractor
- [ ] model_metadata.json is accurate (features, classes, metrics)
- [ ] Synthetic training data covers all 9 scanner domains
- [ ] Cross-validation metrics reflect actual ensemble
- [ ] All existing tests pass
- [ ] New tests for fixes pass
