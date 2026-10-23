# Local Review V2 Independence Specification and Operational Boundary

## 1. Context and Objective

Under Work Order `WO-MSK-REVIEW-AUTHORITY-LOCAL-INDEPENDENCE-00A`, Miskatonic Review Authority transitions from the hardcoded external OpenAI Responses cloud dependency to a provider-neutral independent review interface supporting `LOCAL_LLAMA_CPP` with the local Qwen runtime.

Historical V1 policies and attestations remain archived and unmutated. This document explicitly defines the operational boundary, trust roots, and narrower local-process independence guarantee of V2.

## 2. Narrower Local-Process Independence Guarantee

### What V1 Guaranteed (External Cloud Independence):
- Total physical isolation: review inference was executed by a third-party remote API provider (OpenAI) outside the local host environment.
- Separate network origin, separate execution infrastructure, and independent cloud service boundaries.

### What V2 Guarantees (Local-Process Host Isolation):
In zero-API-cost / offline local mode, the reviewer and model run on the same physical host as the agent environment, but under strict operating-system-level process, filesystem, and identity boundaries:
1. **Separate Service Identity**: The reviewer runs strictly as the unprivileged system user `msk-local-reviewer` (`uid != 1000`, `username != "kowen9024"`).
2. **Workspace Isolation**: Reviewer execution takes place outside `/home/kowen9024` in `/var/lib/miskatonic/local-reviewer` and `/opt/miskatonic/local-reviewer`.
3. **Read-Only Source Guarantee**: Candidate checkouts are inspected in read-only mode (`0555`/`0444`) with write probes failing closed (`CANDIDATE_CHECKOUT_NOT_READONLY`).
4. **No Code Execution Under Signing Credentials**: Candidate code, tests, or scripts are never executed under reviewer signing credentials. Only read-only git tree inspection commands are permitted.
5. **Private Key Segregation**:
   - The GitHub App private key (`MSK_REVIEW_APP_PRIVATE_KEY`) resides exclusively in GitHub Actions secrets and is never deployed to the local inference host.
   - The local reviewer private key (`/etc/miskatonic/local-reviewer/reviewer-private.pem`, mode `0400`) is accessible only to `msk-local-reviewer`. The coding agent (`kowen9024`) receives kernel-enforced permission denials (`EACCES`).
6. **No Public Endpoint**: The local model runtime (`llama-server`) listens strictly on `127.0.0.1:11434` with non-loopback exposure prohibited.

## 3. Supplementation of Independent Scientific Checking

The local LLM supplements deterministic prior verification; it never replaces it.
Every review requires:
- Pre-execution deterministic prior verification (`prior-verify`) passing with an exact candidate digest match.
- Exact model weights SHA-256 (`8ed54a3ef17bef0524c4f3d8258cfffe9446cd68186d773d6045d9be762f94c9`) and server binary SHA-256 (`9bae04c64b3e1b2c4dd4b13e92544cd1ac12b0c941d19bd3c23283b54a3f5183`).
- Complete review coverage across 100% of full-diff files and bytes in bounded context slices.
- Explicit uncertainty metrics, abstention gating, and fail-closed verdict requirements.
- Signed local review receipts verified and admitted by the Miskatonic Review Authority GitHub App.
