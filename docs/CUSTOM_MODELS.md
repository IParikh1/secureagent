# Custom Model Training Guide

SecureAgent ships with a baseline ML model for risk scoring, but supports custom model training for organization-specific needs.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Model Loading Flow                        │
├─────────────────────────────────────────────────────────────┤
│  1. Check for organization's custom model                   │
│  2. Fall back to baseline model if no custom model          │
│  3. Heuristic scoring as final fallback (offline mode)      │
└─────────────────────────────────────────────────────────────┘
```

## When to Train a Custom Model

| Scenario | Recommendation |
|----------|----------------|
| Using SecureAgent out-of-the-box | Use baseline model |
| Industry-specific compliance (HIPAA, PCI-DSS) | Train with industry preset |
| High false positive rate | Train with feedback data |
| Proprietary agent frameworks | Full custom training |
| Different risk tolerance | Use risk tolerance presets |

## Retraining Strategies

### 1. Transfer Learning (Recommended for Most Cases)

Fine-tunes the baseline model on your data while preserving general knowledge.

```bash
# Train a healthcare-focused model
secureagent ml train --data your_findings.json --preset healthcare --register

# Train for financial services
secureagent ml train --data your_findings.json --preset finance --register
```

**Best for:**
- Industry-specific compliance
- Organization-specific policies
- 500-2000 labeled samples available

### 2. Feedback Loop Learning

Model learns from user accept/dismiss decisions over time.

```bash
# Initial setup
secureagent ml train --data feedback_data.json --preset feedback_driven --register

# Continuous improvement (run periodically)
secureagent ml train --data updated_feedback.json --preset feedback_driven --name model-v2
```

**Best for:**
- Reducing false positives
- Adapting to organization patterns
- 200+ feedback samples

### 3. Ensemble Blending

Combines baseline model with custom model predictions.

```bash
# Conservative (more flags, fewer false negatives)
secureagent ml train --data your_data.json --preset high_security --register

# Permissive (fewer flags, reduced noise)
secureagent ml train --data your_data.json --preset low_friction --register
```

**Best for:**
- Adjusting risk tolerance
- Balancing security vs. usability
- Quick customization

### 4. Active Learning

Model requests labels for uncertain predictions to improve efficiently.

```bash
secureagent ml train --data initial_data.json --preset active_learning --register
```

**Best for:**
- Limited labeled data (< 200 samples)
- Efficient labeling budget
- Cold-start situations

### 5. Full Retrain

Train from scratch on organization data only.

```bash
secureagent ml train --data comprehensive_data.json --preset custom_agents --register
```

**Best for:**
- Proprietary frameworks not in baseline
- Completely different tech stack
- 1500+ labeled samples

## Retraining Presets Reference

### Industry-Specific

| Preset | Description | Min Samples |
|--------|-------------|-------------|
| `healthcare` | HIPAA-focused, PHI protection emphasis | 1000 |
| `finance` | PCI-DSS, SOX compliance focus | 1000 |
| `government` | FedRAMP, strict security controls | 800 |

### Risk Tolerance

| Preset | Description | Blend Weight |
|--------|-------------|--------------|
| `high_security` | Conservative, flags more issues | 0.3 (stricter) |
| `balanced` | Default balance | 0.5 |
| `low_friction` | Permissive, reduces noise | 0.7 (lenient) |

### Tech Stack

| Preset | Description | Min Samples |
|--------|-------------|-------------|
| `aws_heavy` | AWS-centric infrastructure | 500 |
| `azure_heavy` | Azure-centric infrastructure | 500 |
| `multi_cloud` | Multi-cloud environments | 800 |

### Training Workflow

| Preset | Strategy | Min Samples |
|--------|----------|-------------|
| `feedback_driven` | Learn from user decisions | 200 |
| `active_learning` | Request labels for uncertain samples | 100 |
| `custom_agents` | Full retrain for proprietary frameworks | 1500 |

## Preparing Training Data

### Data Format

Training data should be a JSON file with findings:

```json
{
  "findings": [
    {
      "rule_id": "MCP-002",
      "title": "Hardcoded API Key",
      "description": "OpenAI API key found in configuration",
      "severity": "critical",
      "domain": "mcp",
      "risk_label": 1,  // 1 = high risk, 0 = low risk
      "context": {
        "file_path": "/config/mcp.json",
        "snippet": "sk-proj-..."
      }
    }
  ]
}
```

### Collecting Feedback Data

Export user feedback from SecureAgent:

```bash
# Export feedback history
secureagent feedback export --output feedback_data.json

# Filter by date range
secureagent feedback export --since 2024-01-01 --output recent_feedback.json
```

### Generating Synthetic Data

Bootstrap training with synthetic data:

```bash
# Generate 5000 synthetic samples
secureagent ml generate-data training_data.json --samples 5000

# Adjust high-risk ratio
secureagent ml generate-data training_data.json --samples 5000 --high-risk-ratio 0.4
```

## Training Workflow

### Step 1: Get Recommended Preset

```bash
secureagent model recommend --industry healthcare --samples 1200
```

### Step 2: Train Model

```bash
secureagent ml train \
  --data your_data.json \
  --preset healthcare \
  --name healthcare-model-v1 \
  --register
```

### Step 3: Evaluate Model

```bash
secureagent ml evaluate test_data.json --model ~/.secureagent/models/healthcare-model-v1.pkl
```

### Step 4: Cross-Validate

```bash
secureagent ml cross-validate --samples 2000 --folds 10
```

### Step 5: Use Custom Model

```bash
# Analyze with custom model
secureagent analyze risk ./config.json --model healthcare-model-v1

# Scan with custom model
secureagent mcp scan ./config.json --risk-score --model healthcare-model-v1
```

## Model Management

### List Registered Models

```bash
secureagent model list
```

### View Model Details

```bash
secureagent model info healthcare-model-v1
```

### Export for Deployment

```bash
secureagent model export healthcare-model-v1 -o ./deploy/model.pkl
```

### Import Shared Model

```bash
secureagent model import ./shared_model.pkl --id team-model-v1
```

### Verify Integrity

```bash
secureagent model verify healthcare-model-v1
```

## Best Practices

### 1. Start with Baseline + Feedback

Don't train a custom model immediately. Use the baseline model and collect feedback data first.

### 2. Version Your Models

Use semantic versioning for model names:
- `healthcare-model-v1.0.0` - Initial release
- `healthcare-model-v1.1.0` - Added new training data
- `healthcare-model-v2.0.0` - Changed strategy/architecture

### 3. Monitor Model Drift

Periodically evaluate your custom model against new data:

```bash
# Weekly evaluation
secureagent ml evaluate latest_findings.json --model your-model
```

### 4. Keep Baseline as Fallback

Always maintain the ability to fall back to the baseline model:

```bash
# Use baseline explicitly
secureagent analyze risk ./config.json --model baseline
```

### 5. Document Training Data Sources

Track where your training data comes from for reproducibility and compliance.

## Troubleshooting

### Model Performance Degraded

1. Check for data drift in recent findings
2. Re-evaluate on held-out test set
3. Consider retraining with recent data

### High False Positive Rate

1. Use `low_friction` preset
2. Train with user dismiss feedback
3. Adjust classification threshold

### High False Negative Rate

1. Use `high_security` preset
2. Add more high-risk samples to training data
3. Lower classification threshold

### Model Not Loading

```bash
# Verify model integrity
secureagent model verify your-model

# Check model exists
secureagent model info your-model
```
