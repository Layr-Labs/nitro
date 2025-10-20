# EigenDA Fork Management Runbook


## Releasing New Consensus Roots
---

### 1. Overview

Consensus roots define the canonical state transition machine for validator challenge and defense logic.  
Each release includes:

- **`module_root.txt`** — merkle root generated from the library and core binary wasm modules extracted vai `replay.wasm`.
- **`replay.wasm`** — L2 state transition replay script executed off-chain by validators and used to referee disputes.
- **`machine.wavm.br`** — Brotli compressed binary of the arbitrator machine used for executing `replay.wasm`.

Artifacts are built deterministically, fingerprinted in CI, and distributed via GitHub releases.  
Nitro software references them via a `download-machine.sh` script that fetches these artifacts by version tag. For EigenDA, we use `download-machine-eigenda.sh`.

---

### 2. Prerequisites

- Local environment has build toolchain (Docker + buildx). See [here](https://docs.arbitrum.io/run-arbitrum-node/nitro/build-nitro-locally) for setup instructions.
---

### 3. Step-by-Step Workflow

#### Step 1 — Generate Consensus Artifact

First make sure you're on the latest `eigenda` branch of the nitro directory and have a clean build target directory:
```bash
git checkout eigenda && make clean
```


Now generate the consensus artifacts via:
```bash
make build-replay-env
```

This command:
- Compiles arbitrator crates and symlinks dependencies.
- Builds both `replay.wasm` and `machine.wasm.br` deterministically.
- Outputs fingerprints for the module root into `module-root.txt`.

The artifacts should be generated under `target/machines/latest` and can be validated for recency by running
`ls -al`.

#### Step 2 — Publish Artifact Release

1. Draft a **pre-release** on GitHub:
   - Title: `eigenda-consensus-**`
   - Attach:
     - `replay.wasm`
     - `machine.wavm.br`
     - `module-root.txt`

2. Mark as **Pre-release** to allow for local validations and testing before marking as "production ready".

---

#### Step 3 — Update Dockerfile

Edit the Nitro Dockerfile to update artifact references:

```Dockerfile
RUN ./download-machine-eigenda.sh consensus-eigenda-vX.Y.Z ${MODULE_ROOT}
```

- New docker builds will automatically fetch and fingerprint the new machine.
- Docker build fails if fingerprints mismatch via `./validate-wasm-module-root.sh` script, ensuring artifact integrity.

Commit and push:

```bash
git commit -am "update consensus root to vX.Y.Z"
git push origin consensus-root-vX.Y.Z
```

---
