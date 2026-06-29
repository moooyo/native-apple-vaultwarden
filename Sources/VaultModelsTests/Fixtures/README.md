# Real Vaultwarden `/api/sync` fixture

This optional fixture asserts that `SyncResponse` decodes a real server's sync
payload with zero dropped ciphers — the strongest proof that the wire models and
case-insensitive decoding match production Vaultwarden.

## Capture procedure

1. Start a throwaway Vaultwarden in Docker:
   `docker run --rm -p 8080:80 -e ADMIN_TOKEN=dev vaultwarden/server:latest`
2. Create a THROWAWAY account with a KNOWN PBKDF2 KDF (Settings → Security →
   set KDF = PBKDF2, iterations = 600000). Add at least one of each item type you
   want to cover: a Login (with URIs + a passkey if possible), a Card, an Identity,
   a Secure Note, an SSH key, plus a Folder.
3. Authenticate and capture the sync payload:
   - `POST /identity/connect/token` to get an access token.
   - `GET /api/sync` with `Authorization: Bearer <token>`.
4. Save the raw JSON response verbatim as
   `Sources/VaultModelsTests/Fixtures/sync-vaultwarden.json`.

## Running the gated check

The `Fixtures/` directory is excluded from the build target, so the check reads
the file from disk at runtime and is gated behind an env var. With the file in
place:

```bash
TESSERA_FIXTURES=1 swift run VaultModelsTests
```

The check (`checkRealSyncFixture`) decodes the file into `SyncResponse` and
asserts:
- decoding does not throw,
- `droppedCipherErrors` is empty (every cipher's EncString fields parsed),
- there is at least one cipher and one folder.

Without `TESSERA_FIXTURES=1` (or without the file) the check is skipped, so CI and
hosts without the fixture still pass.

## Caution

The captured `/api/sync` contains the account's (encrypted) vault contents and
profile keys. Use a THROWAWAY account only and **never commit** a real user's
fixture. This file is git-ignored guidance only; if you add the JSON, keep it out
of version control.
