"""Smoke and validation tests for the pySigma compilation engine."""

from app.tools.sigma_engine import SigmaValidationResult, validate_and_compile_sigma

SAMPLE_PROCESS_CREATION_RULE = """
title: Suspicious Encoded PowerShell Execution
id: 12345678-1234-4321-8765-123456789abc
status: experimental
description: Detects encoded PowerShell command lines excluding explorer parent processes.
author: SecOps Agent
date: 2026-11-26
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  filter_legit:
    ParentImage|endswith: '\\explorer.exe'
  condition: selection and not filter_legit
falsepositives:
  - Administrative scripts launched from Windows Explorer
level: high
"""

SAMPLE_FILE_EVENT_RULE = """
title: Suspicious Payload Dropped in Temp Directory
id: 87654321-4321-1234-5678-cba987654321
status: experimental
description: Detects executable file creation in Windows Temp directory.
tags:
  - attack.persistence
  - attack.t1547
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|contains: '\\AppData\\Local\\Temp\\'
    TargetFilename|endswith: '.exe'
  condition: selection
level: medium
"""


def test_compile_valid_process_creation_rule() -> None:
    result = validate_and_compile_sigma(SAMPLE_PROCESS_CREATION_RULE)

    assert isinstance(result, SigmaValidationResult)
    assert result.is_valid is True
    assert result.error is None
    assert result.splunk_spl is not None
    assert result.sentinel_kql is not None

    # Sysmon pipeline maps process_creation -> EventID=1 for Splunk
    assert "EventID=1" in result.splunk_spl
    assert "powershell.exe" in result.splunk_spl
    assert "NOT" in result.splunk_spl

    # Sentinel KQL uses Kusto syntax without Sysmon EventID leakage
    assert "powershell.exe" in result.sentinel_kql
    assert "not(" in result.sentinel_kql.lower()
    assert "EventID" not in result.sentinel_kql


def test_compile_file_event_rule() -> None:
    result = validate_and_compile_sigma(SAMPLE_FILE_EVENT_RULE)

    assert result.is_valid is True
    assert result.error is None
    assert result.splunk_spl is not None and "EventID=11" in result.splunk_spl
    assert result.sentinel_kql is not None and "TargetFilename" in result.sentinel_kql


def test_invalid_yaml_syntax_returns_error() -> None:
    bad_yaml = "title: Broken\ndetection:\n  selection: [unclosed"
    result = validate_and_compile_sigma(bad_yaml)

    assert result.is_valid is False
    assert result.error is not None
    assert result.splunk_spl is None
    assert result.sentinel_kql is None


def test_invalid_sigma_condition_returns_error() -> None:
    bad_sigma = """
title: Missing Selection Reference
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: undefined_selection
"""
    result = validate_and_compile_sigma(bad_sigma)

    assert result.is_valid is False
    assert result.error is not None and "undefined_selection" in result.error


def test_empty_yaml_returns_error() -> None:
    result = validate_and_compile_sigma("   \n  ")

    assert result.is_valid is False
    assert result.error is not None
