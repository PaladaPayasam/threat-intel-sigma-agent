---
name: sigma-rule-engineering
description: Exact API patterns and YAML standards for generating, validating, and transpiling Sigma detection rules using pySigma 2.1+ and LangGraph.
---

# Sigma Rule Engineering Standard

## 1. `pySigma 2.1.2` Validation & Transpilation Pattern
- Always strip optional markdown code fences (` ```yaml ` ... ` ``` `) before passing YAML to `SigmaCollection.from_yaml()`.
- Parse a **fresh** `SigmaCollection.from_yaml()` instance per backend: applying `sysmon_pipeline()` mutates rule detections in place (for example, injecting `EventID`), which would otherwise leak into subsequent backend conversions.
- **Splunk SPL:** Use `SplunkBackend(processing_pipeline=sysmon_pipeline())`.
- **Microsoft Sentinel / Defender KQL:** Resolve the backend via `sigma.backends.microsoft365defender.backends["microsoft365defender"]` (which maps to `KustoBackend` in `pySigma-backend-microsoft365defender`).

```python
from sigma.backends.microsoft365defender import backends as _m365_backends
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline

Microsoft365DefenderBackend = _m365_backends["microsoft365defender"]

splunk_queries = SplunkBackend(processing_pipeline=sysmon_pipeline()).convert(
    SigmaCollection.from_yaml(cleaned_yaml)
)
sentinel_queries = Microsoft365DefenderBackend().convert(
    SigmaCollection.from_yaml(cleaned_yaml)
)
```

## 2. Required Sigma YAML Structure
Every generated Sigma rule must include:
- `title`: Concise, descriptive threat rule title.
- `id`: Valid UUIDv4 string.
- `status`: `experimental`
- `description`: Clear summary of the adversary behavior detected.
- `tags`: Lowercase MITRE ATT&CK tags (e.g., `attack.execution`, `attack.t1059.001`).
- `logsource`: Grounded `category` and `product` (e.g., `category: process_creation`, `product: windows`).
- `detection`:
  - `selection`: Grounded Sigma field names (e.g., `Image`, `CommandLine`, `ParentImage`, `TargetFilename`).
  - `filter_legit`: Benign exclusions to reduce false positives.
  - `condition: selection and not filter_legit`
- `falsepositives`: List of expected benign triggers.
- `level`: Severity (`low`, `medium`, `high`, or `critical`).

## 3. LangGraph Retry Loop
- On validation or transpilation failure, pass the exact `pySigma` / `PyYAML` error string back into `generate_sigma` state and retry up to 3 times.
