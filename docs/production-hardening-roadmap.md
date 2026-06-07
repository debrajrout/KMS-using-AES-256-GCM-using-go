# Production Hardening Roadmap

Each phase should be completed and verified independently. Do not deploy this
service to production until all critical phases and their operational controls
are complete.

## Step 1: Repository Security Baseline

Status: implemented in the working tree; credential rotation remains an
operator action.

- Prevent common secret and private-key files from being committed.
- Provide a placeholder-only development environment template.
- Scan current repository contents for secrets in CI.
- Run tests, module verification, and reachable-vulnerability scanning in CI.
- Enable weekly dependency update proposals.
- Document security reporting and historical credential-exposure response.
- Rotate exposed credentials before any production deployment.

## Step 2: HTTP and Request Hardening

Status: implemented in the working tree.

- Enforce allowed HTTP methods.
- Add request-body size limits and strict JSON decoding.
- Configure server read, write, header, and idle timeouts.
- Propagate request contexts and add dependency-operation deadlines.
- Add real rate limiting and consistent JSON error responses.
- Add focused handler and middleware tests.

## Step 3: Versioned Encryption Envelope

- Define a versioned ciphertext envelope.
- Bind key ID, tenant, purpose, and algorithm metadata with AES-GCM AAD.
- Validate envelopes before decryption.
- Add test vectors and tamper-detection tests.

## Step 4: DEK Ownership and Authorization

- Persist tenant, service owner, purpose, status, and timestamps with each DEK.
- Enforce ownership in storage queries, not only in handlers.
- Replace broad role checks with explicit operation policies.
- Add authorization-boundary and cross-tenant denial tests.

## Step 5: External Master-Key Provider

- Define a key-wrapping provider interface.
- Integrate a durable KMS, HSM, or Vault provider.
- Stop loading raw production master keys into application configuration.
- Document availability, access policy, and recovery requirements.

## Step 6: Safe Key Lifecycle and Rotation

- Persist active key versions consistently across replicas.
- Implement DEK rewrapping with resumable jobs.
- Add key states, disablement, pending deletion, and retention periods.
- Add approval controls for rotation and destructive operations.
- Test restart, rollback, partial-failure, and multi-replica behavior.

## Step 7: Auditability and Observability

- Add structured logs with request and correlation IDs.
- Emit immutable audit events for all key operations.
- Add health, readiness, metrics, and tracing endpoints.
- Define alerts and service-level objectives.

## Step 8: Deployment and Operational Readiness

- Add reproducible container builds and hardened runtime configuration.
- Add deployment manifests and infrastructure-as-code.
- Document backup, restore, disaster recovery, and incident procedures.
- Add release, rollback, and production-readiness checklists.
- Complete threat modeling and an independent security review.
