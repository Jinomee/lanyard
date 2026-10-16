# Releasing

## One-time setup (maintainer TODOs)

### 1. Update-signing key (Ed25519, minisign-compatible)

The app only offers an update if `manifest.json` carries a valid signature
from the key embedded at build time (`internal/update/pubkey.txt`, currently
`UNSET`, so update checks report "not available in this build").

On a trusted machine (not CI):

```sh
go run ./cmd/lanyard-release keygen -pub internal/update/pubkey.txt -key lanyard-release.key
# or equivalently: minisign -G -p internal/update/pubkey.txt -s lanyard-release.key
```

* Commit `internal/update/pubkey.txt`. It is public.
* In GitHub → Settings → Secrets and variables → Actions, add:
  * `MINISIGN_SECRET_KEY`: the full contents of `lanyard-release.key` (the
    encrypted key file).
  * `MINISIGN_PASSWORD`: its password.
* Store `lanyard-release.key` and the password offline (password manager plus
  an offline backup). **Never commit the private key.** `.gitignore` does not
  protect you here; double-check `git status`.
* Losing the key means old installs can never verify updates again. Users
  would have to download a new version manually once.

### 2. Update mirror (for players who can't reach GitHub)

Set `updateServer` in `internal/brand/brand.json` (placeholder:
`https://updates.example.com/lanyard/`). The release workflow uploads to it by
rsync over SSH when these are configured:

* variables `MIRROR_HOST` (`user@host`) and `MIRROR_PATH` (the directory that
  serves `updateServer`),
* secret `MIRROR_SSH_KEY` (a deploy key allowed only to write that directory).

Layout on the server: `<updateServer>/manifest.json` (+ `.minisig`) for the
latest release, and `<updateServer>/<version>/<files>` for downloads. Any
static file host works, for example a server in mainland China or an
object-storage bucket with a CDN. Because the manifest is signed, the mirror
does not need to be trusted.

### 3. Code signing via SignPath Foundation (free for OSS)

Unsigned Windows executables trigger SmartScreen warnings. To fix this:

1. Apply at <https://signpath.org/apply> (needs: OSI license ✔, public repo,
   release builds from CI ✔, no unsigned binaries in other channels).
2. In SignPath, create a project with two artifact configurations:
   `exe` (a single PE file) and `installer` (a single PE file).
3. Add repository **variables** `SIGNPATH_ORGANIZATION_ID`,
   `SIGNPATH_PROJECT_SLUG`, `SIGNPATH_POLICY_SLUG` and the **secret**
   `SIGNPATH_API_TOKEN`.
4. The signing steps in `.github/workflows/release.yml` turn on automatically
   once `SIGNPATH_ORGANIZATION_ID` is set. The flow is: sign `LANyard.exe` →
   rebuild the NSIS installer around the signed exe → sign the installer.

## Cutting a release

1. Update `CHANGELOG` notes in the tag message or the GitHub release text
   afterwards.
2. Run the [manual test](MANUAL_TEST.md) on a release candidate (tag
   `v1.2.3-rc.1`; pre-releases are published as such).
3. `git tag v1.2.3 && git push origin v1.2.3`.
4. The `Release` workflow builds the app, installer and headless cores,
   writes `manifest.json` (SHA-256 of every file, GitHub and mirror URLs),
   signs it, **verifies the signature with the key embedded in the app**
   (refusing to publish otherwise), creates the GitHub release and uploads to
   the mirror.
5. Check one download from each source against `SHA256SUMS.txt`.

## Renaming the product

Edit `internal/brand/brand.json`, then run `go run ./tools/brandsync` (updates
`gui/wails.json`: executable name, version info, installer, URI scheme). The
join-code prefix `LY1-` is a protocol constant and does not change.
