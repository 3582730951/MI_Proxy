param(
    [string]$EvidenceDir = "dist",
    [switch]$RequireExternalEvidence
)

$ErrorActionPreference = "Stop"

function Add-Failure {
    param([string]$Message)
    $script:failures.Add($Message) | Out-Null
}

function Find-Evidence {
    param([string[]]$Patterns)
    foreach ($pattern in $Patterns) {
        $match = Get-ChildItem -Path $EvidenceDir -Filter $pattern -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($null -ne $match) {
            return $match.FullName
        }
    }
    return $null
}

function Test-TrueValue {
    param([string]$Value)
    return $Value -in @("1", "true", "True", "TRUE", "yes", "YES")
}

$failures = [System.Collections.Generic.List[string]]::new()
$found = [ordered]@{}

if (-not (Test-Path -LiteralPath $EvidenceDir)) {
    Add-Failure "evidence directory not found: $EvidenceDir"
} else {
    $found.sbom = Find-Evidence @("sbom*.json")
    $found.licenseScan = Find-Evidence @("license-scan*.json")
    $found.iacScan = Find-Evidence @("iac-scan*.json")
    $found.acceptance = Find-Evidence @("acceptance*.json")
    $found.provenance = Find-Evidence @("provenance*.json")

    foreach ($name in @("sbom", "licenseScan", "iacScan", "acceptance", "provenance")) {
        if ([string]::IsNullOrWhiteSpace($found[$name])) {
            Add-Failure "missing local $name evidence in $EvidenceDir"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($found.iacScan)) {
        $iacScan = Get-Content -Raw -LiteralPath $found.iacScan | ConvertFrom-Json
        $found.iacScanPassed = [bool]$iacScan.passed
        if (-not [bool]$iacScan.passed) {
            Add-Failure "local IaC scan evidence did not pass"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($found.licenseScan)) {
        $licenseScan = Get-Content -Raw -LiteralPath $found.licenseScan | ConvertFrom-Json
        $found.licenseScanPassed = [bool]$licenseScan.passed
        if (-not [bool]$licenseScan.passed) {
            Add-Failure "local license scan evidence did not pass"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($found.acceptance)) {
        $acceptance = Get-Content -Raw -LiteralPath $found.acceptance | ConvertFrom-Json
        $found.acceptanceComplete = [bool]$acceptance.complete
    }

    if (-not [string]::IsNullOrWhiteSpace($found.provenance)) {
        $provenance = Get-Content -Raw -LiteralPath $found.provenance | ConvertFrom-Json
        $found.provenanceIncludesLicenseScan = [bool]($provenance.artifacts | Where-Object { $_.path -like "*license-scan*" } | Select-Object -First 1)
        $found.provenanceIncludesIaCScan = [bool]($provenance.artifacts | Where-Object { $_.path -like "*iac-scan*" } | Select-Object -First 1)
        if (-not [bool]$found.provenanceIncludesLicenseScan) {
            Add-Failure "local provenance must include license scan evidence"
        }
        if (-not [bool]$found.provenanceIncludesIaCScan) {
            Add-Failure "local provenance must include IaC scan evidence"
        }
    }
}

if ($RequireExternalEvidence) {
    $trueChecks = [ordered]@{
        MAIN_BRANCH_PROTECTED = $env:MAIN_BRANCH_PROTECTED
        HUMAN_REVIEW_APPROVED = $env:HUMAN_REVIEW_APPROVED
        GPT55_REVIEW_APPROVED = $env:GPT55_REVIEW_APPROVED
        CANARY_24H_PASSED = $env:CANARY_24H_PASSED
    }
    foreach ($key in $trueChecks.Keys) {
        if (-not (Test-TrueValue $trueChecks[$key])) {
            Add-Failure "$key must be true"
        }
    }

    $referenceChecks = [ordered]@{
        STAGING_DAST_EVIDENCE = $env:STAGING_DAST_EVIDENCE
        FULL_LOAD_EVIDENCE = $env:FULL_LOAD_EVIDENCE
        TOXIPROXY_CHAOS_EVIDENCE = $env:TOXIPROXY_CHAOS_EVIDENCE
        COSIGN_SIGNATURE_REF = $env:COSIGN_SIGNATURE_REF
        SLSA_PROVENANCE_REF = $env:SLSA_PROVENANCE_REF
    }
    foreach ($key in $referenceChecks.Keys) {
        if ([string]::IsNullOrWhiteSpace($referenceChecks[$key])) {
            Add-Failure "$key must point to release evidence"
        }
    }
}

$result = [ordered]@{
    generatedAt = (Get-Date).ToUniversalTime().ToString("o")
    evidenceDir = $EvidenceDir
    requireExternalEvidence = [bool]$RequireExternalEvidence
    passed = ($failures.Count -eq 0)
    localEvidence = $found
    failures = @($failures)
}

$result | ConvertTo-Json -Depth 8

if ($failures.Count -gt 0) {
    exit 1
}
