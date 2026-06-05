# AGENTS.md

## Rule Compiler Requirements
- Private CIDR and mainland China direct rules must outrank proxy and WARP rules.
- Google Scholar exclusions must outrank WARP include rules.
- Rule conflicts must block publish before active config replacement.
- Every rule update must produce a diff report.
- `tests/rules/domain-classification` must pass at 100%.

