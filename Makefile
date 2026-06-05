.PHONY: test rule-test security-scan license-scan iac-scan sbom acceptance lint typecheck e2e load-smoke dast-smoke api-fuzz chaos-smoke provenance docker-up-test

test:
	go test ./...

rule-test:
	go test ./packages/rulecompiler

security-scan:
	go run ./cmd/security-scan

license-scan:
	go run ./cmd/license-scan

iac-scan:
	go run ./cmd/iac-scan

sbom:
	go run ./cmd/sbom > sbom.json

acceptance:
	go run ./cmd/acceptance > acceptance-local.json

lint:
	go test ./...

typecheck:
	go test ./...

e2e:
	go test ./services/controlplane ./agent

load-smoke:
	go run ./cmd/load-smoke

dast-smoke:
	go run ./cmd/dast-smoke

api-fuzz:
	go run ./cmd/api-fuzz

chaos-smoke:
	go run ./cmd/chaos-smoke

provenance:
	go run ./cmd/provenance dist/sbom.json dist/license-scan.local.json dist/iac-scan.local.json dist/acceptance-local.json > dist/provenance.local.json

docker-up-test:
	docker compose up --build -d
	docker compose ps
