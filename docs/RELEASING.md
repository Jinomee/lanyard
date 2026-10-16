# Releasing

## One-time setup (maintainer TODOs)

### 1. Update-signing key (Ed25519, minisign-compatible)

The app only offers an update if `manifest.json` carries a valid signature
from the key embedded at build time (`internal/update/pubkey.txt`). The
LANyard key (ID `85FFA6E20F740D07`) is set up and committed; a build with the
file set to `UNSET` reports update checks as "not available in this build".
These steps are for a fork, or for replacing a lost key.

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

The app checks GitHub first (3 s timeout), then the mirror set as
`updateServer` in `internal/brand/brand.json`:
**`https://updates.jinome.org/lanyard/`**. Because the manifest is signed, the
mirror does not need to be trusted. It only has to serve the files
byte-for-byte unchanged.

**Layout:** `<updateServer>/manifest.json` (+ `.minisig`) describes the latest
**stable** release; `<updateServer>/<version>/<files>` holds every release's
files (pre-releases included, e.g. `0.1.0-rc.1/`).

**Server** (jinome.org host, Australia):

* Files live in `/www/wwwroot/updates.jinome.org/lanyard`, served by nginx
  over HTTPS with a Let's Encrypt certificate (auto-renewed).
* Byte-exact: gzip off, correct `Content-Length`, Range requests supported,
  real 404s, no directory listing, no access log.
* Caching: `manifest.json` and `manifest.json.minisig` are sent with
  `no-cache`, so clients see a new release promptly. `<version>/*` is
  `public, max-age=31536000, immutable`. **Never publish different bytes under
  a version that was already released.** Fix problems by releasing a new
  version, not by re-running the release workflow for an old tag.
* Uploads use the `lanyard-deploy` user, key-only. Its key is forced to
  `rrsync -wo -no-del /www/wwwroot/updates.jinome.org/lanyard`: write-only,
  no deletes, no shell, every path relative to that directory. Old versions
  therefore stay on the mirror until removed by hand on the server.
* Reachability (Globalping, 2026-10-16): 8/8 mainland China probes (Beijing,
  Shanghai, Guangzhou, Shenzhen, Hangzhou, Ningbo, Wuhan, Nanjing) got HTTP 200
  in 1.1–2.4 s; Hong Kong, Tokyo and Singapore too. These were mostly cloud or
  backbone probes, and large-file download speed from Australia hasn't been
  measured.

**GitHub configuration** (Settings → Secrets and variables → Actions):

* variables `MIRROR_HOST` = `lanyard-deploy@updates.jinome.org`,
  `MIRROR_PATH` = `.` (relative on purpose: rrsync prefixes absolute paths
  with the mirror directory);
* secret `MIRROR_SSH_KEY` = the deploy key's private half.

**What the release workflow does:** it lists the mirror URL
(`<updateServer>/<version>/<file>`) next to the GitHub URL for every file in
the manifest. After publishing on GitHub it rsyncs `dist/` to `./<version>/`
with `--ignore-existing`, so a re-run never replaces files that were already
published. Then, **only for stable versions** (no `-` in the version) that
are **newer than the mirror's current `manifest.json`**, it rsyncs
`manifest.json` and `manifest.json.minisig` to `./`; re-running the workflow
for an older tag can't roll the mirror back. The workflow must stay
within the deploy key's limits: rsync uploads only, relative paths, no
`--delete`, no other ssh commands.

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
