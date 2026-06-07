# Historical Credential Exposure Response

## Status

The Git history contains a previously committed `.env`, TLS certificate, and
TLS private key. Removing those files from the current branch did not remove
them from existing clones, forks, caches, or Git history.

Do not deploy this repository using any credential or key that appeared in the
historical files.

## Required Response Order

Complete rotation before rewriting history. Rewriting first can destroy the
record needed to identify affected credentials.

1. Record the incident owner, start time, affected environments, and repository
   visibility.
2. Inventory every value from the historical `.env` without copying values into
   tickets, chat, or logs.
3. Rotate or revoke all exposed credentials:
   - MongoDB credentials embedded in `MONGO_URI`
   - Every key listed in `MASTER_KEYS`
   - The exposed TLS private key and certificate
   - Any Firebase credential referenced by the exposed configuration, if its
     contents or access path may have been exposed
4. Deploy the replacement credentials from an approved secret manager.
5. Verify old credentials and keys no longer grant access.
6. Check MongoDB, Firebase, hosting, and repository audit logs for unauthorized
   use from the first exposure date through revocation.
7. Notify all collaborators that a coordinated history rewrite is scheduled.
8. Rewrite repository history to remove `.env`, `certs/server.key`, and
   `certs/server.crt`, then force-push all affected branches and tags.
9. Require collaborators to delete old clones and clone the sanitized
   repository again.
10. Run a full-history secret scan and record the clean result.

## History Rewrite

Perform this only after rotation and collaborator coordination. Use a fresh
mirror clone and a reviewed `git filter-repo` command. Keep the old repository
in a restricted incident archive only if policy requires it.

Example path-removal command:

```text
git filter-repo --invert-paths --path .env --path certs/server.key --path certs/server.crt
```

Do not run the example blindly against the working repository. Confirm all
affected paths, branches, tags, forks, release artifacts, and deployment caches
first.

## Closure Criteria

- All exposed credentials are revoked or rotated.
- Replacement master keys are recoverable and backed up according to policy.
- Audit logs have been reviewed and findings documented.
- Remote Git history no longer contains the exposed files.
- A full-history secret scan passes.
- Collaborators no longer retain or use old clones.
- Preventive CI checks are required on protected branches.
