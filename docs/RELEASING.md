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

### 3. Code signing (deferred: v1 ships unsigned)

v1 is released **unsigned**. Windows SmartScreen and some antivirus products
will warn until the app is signed and has built reputation. The README tells
players what to do ("Windows protected your PC" section). Options for later:

| Option | Cost | Notes |
|---|---|---|
| SignPath Foundation | free | Wants an established project (releases, users). Apply once LANyard has some. |
| Certum Open Source Code Signing (SimplySign cloud) | about €49 the first year | Individuals qualify. Each signature needs a one-time code; CI can generate it from a stored TOTP secret behind a manually approved GitHub Environment. |
| Azure Artifact Signing | US$9.99/month | Individuals only in the USA/Canada. Official GitHub Action. |

With any of them, reputation builds on the **certificate**, so it carries over
between releases. Unsigned files start from zero every release. The SignPath
steps in `.github/workflows/release.yml` are already in place and skip
themselves until `SIGNPATH_ORGANIZATION_ID` is set. Another provider would
replace those steps (sign `LANyard.exe` → rebuild installer → sign installer).

### 4. Before announcing each release: antivirus false positives

New unsigned network software is often flagged, especially by the antivirus
products common in mainland China. After the release workflow finishes:

- [ ] Upload the installer and the portable exe to [VirusTotal](https://www.virustotal.com/) and link the reports in the release notes.
- [ ] Submit both files to Microsoft as **Software developer → Incorrectly detected as malware/malicious**: <https://www.microsoft.com/en-us/wdsi/filesubmission>.
- [ ] 360 安全卫士: submit through 360's software/developer platform or in-app 误报反馈. Developers have reported 360 asking for ID documents. Check their current requirements.
- [ ] 腾讯电脑管家 and 火绒: use each product's in-app 误报反馈 / 样本提交 (false-positive report).
- [ ] Record what was submitted and any detection names in the release issue, so the next release can reference them.

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
