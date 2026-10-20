# Releasing

A release is a `v*` tag. Pushing one runs [.github/workflows/release.yml](.github/workflows/release.yml),
which publishes:

- binaries for Linux and macOS on amd64 and arm64, in `tar.gz` archives with the licence, README and
  changelog, an SPDX SBOM for each archive, and `checksums.txt`, signed with cosign
  (`checksums.txt.sigstore.json`), on a GitHub release whose notes are the version's
  `CHANGELOG.md` section;
- the image `ghcr.io/petersr/spiffex` for `linux/amd64` and `linux/arm64`, built from the same
  binaries, signed with cosign, with build provenance and an SBOM attached;
- the Helm chart `oci://ghcr.io/petersr/charts/spiffex`, with `version` and `appVersion` set from
  the tag, signed with cosign;
- build provenance attestations for the archives, the image and the chart.

Signing is keyless: cosign signs with a short-lived certificate for the workflow's GitHub OIDC
identity, recorded in the public Sigstore transparency log. There are no signing keys to keep.

**A release from a private repository is unsigned and has no attestations**: the workflow skips
both, with a warning, so that the transparency log does not name a private repository. 0.1.0-rc.1
to 0.1.2 were released that way, before the repository went public; 0.1.3 is the first signed
release.

## Versions and tags

Versions follow [Semantic Versioning](https://semver.org/). The tag is `v` and the version:
`v0.1.0`, or `v0.1.0-rc.1` for a prerelease. The image is tagged:

| Tag | Moves to |
|---|---|
| `vX.Y.Z`, `vX.Y.Z-rc.N` | that version only |
| `X.Y` | the newest `vX.Y.*` that is not a prerelease |
| `latest` | the newest version that is not a prerelease |

goreleaser pushes only the version tag. `X.Y` and `latest` move in the last job, once the chart is
out too, so a release that fails halfway never moves them. A tag with a `-` suffix makes a GitHub
prerelease, which never becomes the latest release, and moves neither `X.Y` nor `latest`. Tags
must follow Semantic Versioning without build metadata; the workflow refuses anything else. The chart's version is the tag without the `v`, and its image tag
defaults to `v` and its `appVersion`, so a chart always installs the image of its own release.

## Cutting a release

1. Make sure `main` is green, and run the end-to-end tests on kind, which CI does not
   (`test/e2e/kind.sh`, `kind-helm.sh` and `kind-x509.sh`; CONTRIBUTING.md says how).
2. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add a new empty
   `## [Unreleased]` above it, and update the links at the bottom. The release fails when the
   version has no section, or an empty one; check with `scripts/changelog-section.sh vX.Y.Z`.
3. Update the version in the documentation and manifests that name it (`grep -rn 'v0\.'` finds
   them): `deploy/kubernetes/*.yaml`, `docs/kubernetes.md`, `charts/spiffex/README.md`,
   `README.md`. Set `version` and `appVersion` in `charts/spiffex/Chart.yaml` to the version; the
   workflow sets them from the tag anyway, but the repository should agree.
4. Commit, get it onto `main` through a pull request, then tag the merged commit and push the tag:

   ```bash
   git tag -s vX.Y.Z -m vX.Y.Z
   git push origin vX.Y.Z
   ```

5. The workflow runs the full test suite (`test.yml`) on the tagged commit first, and publishes
   nothing if it fails. It then waits for approval of the `release` environment, the one approval
   point: only the first publishing job runs in it, and the jobs after it run only once it has
   succeeded. It builds and publishes the binaries and the image, then the chart, keeping the
   GitHub release a draft until all of them are out, then publishes the release and moves the
   image's `X.Y` and `latest` tags.

The release job builds with a fixed Go version, set in `release.yml`, so that a release can be
rebuilt bit for bit; raise it with each Go patch release. Archives carry the commit time on every
file.

To try the release build locally, without signing or publishing anything, run
`make release-snapshot` (it needs goreleaser and syft). It builds everything into `dist/` and loads
single-architecture images into Docker; remove `dist/` and those images afterwards.

A failed release can be retried by rerunning the failed jobs, or the whole workflow: goreleaser
reuses the existing draft release and replaces its assets, pushing the image again gives the same
image, and the chart push replaces the chart of that version. Once the release is published, do
not rerun it or move the tag: fix what was wrong and release the next patch version.

## Repository settings

Configure these once, in the repository's settings:

- **An environment named `release`**, with required reviewers and a deployment rule allowing only
  tags matching `v*`. The first publishing job runs in it and the others depend on it, so nothing
  is published without an approval.
- **A tag ruleset** for `refs/tags/v*` restricting creation, update and deletion to maintainers,
  so that only they can start a release and nobody can move a released tag.
- **Actions permissions**: the default `GITHUB_TOKEN` permission can stay read-only; the workflow
  asks for what each job needs.
- **Packages**: the first release creates `spiffex` and `charts/spiffex` on ghcr.io. Make both
  public (package settings, Danger Zone), or nobody can pull them, and check that each package
  lists this repository under "Manage Actions access" with the write role. A package created
  beforehand by hand needs that access granted explicitly.
- **While the repository is private**, check what the plan allows: on a private repository
  without a paid plan, required reviewers on environments and tag rulesets may not be available.
  Then pushing a `v*` tag publishes without any approval, and the only protection is that nobody
  but the owner has write access. Confirm the plan, or accept that.
- **Signatures and attestations start with the first release after the repository goes public.**
  Keyless signing records the repository, workflow path and commit in the public Sigstore
  transparency log, and attestations need a public repository, so from a private repository the
  workflow skips cosign and the attestations with a warning and publishes the release unsigned.
  To sign an earlier release later, the simplest way is to cut a fresh release (the next
  release candidate or patch) once the repository is public. Signing an existing one is possible
  with a `workflow_dispatch` job that has `id-token: write` and `packages: write` and runs
  `cosign sign --yes ghcr.io/petersr/spiffex@<digest>` (and the same for the chart), with the
  digest taken from the release; note that its signature then names that job's run, not the tag,
  so it fails the identity check below, and the archives' `checksums.txt` would have to be signed
  and uploaded by hand as well.

## Verifying a release

You need [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3.1 or newer;
cosign 2 reports "no signatures found" for the image and the chart. The signatures name the
release workflow on a version tag of this repository. Set `VERSION` to the release you are
checking:

```bash
VERSION=X.Y.Z
IDENTITY='^https://github\.com/PeterSR/spiffex/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
OIDC=https://token.actions.githubusercontent.com
```

The image, which prints its digest; then pin the image by that digest:

```bash
cosign verify "ghcr.io/petersr/spiffex:v$VERSION" \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$OIDC"
```

The chart:

```bash
cosign verify "ghcr.io/petersr/charts/spiffex:$VERSION" \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$OIDC"
```

The binaries: verify the checksums file, then the archive against it:

```bash
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$OIDC"
sha256sum --ignore-missing -c checksums.txt
```

The build provenance, with the GitHub CLI:

```bash
gh attestation verify "spiffex_${VERSION}_linux_amd64.tar.gz" --repo PeterSR/spiffex
gh attestation verify "oci://ghcr.io/petersr/spiffex:v$VERSION" --repo PeterSR/spiffex
```

To accept only one release, replace the regular expression with that tag's exact identity:
`--certificate-identity "https://github.com/PeterSR/spiffex/.github/workflows/release.yml@refs/tags/v$VERSION"`.
