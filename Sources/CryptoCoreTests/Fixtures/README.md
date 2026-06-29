# Real Vaultwarden compatibility fixtures

To assert byte-compatibility against a real server (run before merging crypto changes):

1. Start a throwaway Vaultwarden in Docker:
   `docker run --rm -p 8080:80 -e ADMIN_TOKEN=dev vaultwarden/server:latest`
2. Create an account with a KNOWN PBKDF2 KDF (Settings → Security → set KDF = PBKDF2,
   iterations = 600000). Record email, password, iterations.
3. Capture from `POST /identity/connect/token` the `Key` (protected user key EncString)
   and from `GET /api/sync` one cipher's `name` EncString.
4. Save them as `Fixtures/vaultwarden-pbkdf2.json`:
   `{ "email": "...", "password": "...", "iterations": 600000,
      "protectedUserKey": "2.<iv>|<ct>|<mac>", "cipherName": "2.<iv>|<ct>|<mac>",
      "expectedCipherName": "<plaintext>" }`
5. Add a test that derives the master key, stretches, decrypts `protectedUserKey` to the
   UserKey, then decrypts `cipherName` and asserts it equals `expectedCipherName`.

NOTE: fixtures contain a real password for a THROWAWAY account only. Never commit a
fixture for a real user. Gate the fixture test behind an env var (e.g. `TESSERA_FIXTURES=1`)
so CI without the file still passes.
