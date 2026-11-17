# sast-grader image

The task grader (`task_format/grade.py`, v3.3) baked into a small image that v4 tasks use as the base of their separate verifier (`tests/Dockerfile`). Tasks no longer carry `grade.py`; they carry only `test.sh` and their ground truth, and inherit the grader from this image.

## Contents

| Path | What |
|---|---|
| `/opt/grader/grade.py` | Byte-identical copy of `task_format/grade.py`, staged by `build.sh` |
| `/opt/grader/grade` | Entry point. Runs `grade.py` with the same arguments, then stamps the result (below). Scoring is untouched |
| `/opt/grader/VERSION` | Image version, e.g. `3.3.0`. Major and minor must match grade.py's `GRADER_VERSION` (`v3.3`); `build.sh` refuses to build otherwise |
| env `GRADER_IMAGE` | The image reference baked in at build time (`.../sast-grader:3`) |

Base is `python:3.12-slim` pinned by digest (the same base as the task images). The grader uses only the standard library, needs no network at runtime, and runs as the non-root user `grader` (uid 10001). `/opt/grader` is root-owned and read-only to that user; `/logs/verifier` is owned by it.

Usage, as in a task's `tests/test.sh`:

```bash
/opt/grader/grade --sarif /app/output/findings.sarif --truth /tests/ground_truth.json --out /logs/verifier
/opt/grader/grade --check-truth --truth tests/ground_truth.json --repo environment/repo   # authoring check
```

### Version stamp

`grading_detail.json` gets `grader_version` (`v3.3`), `grader_image` and `grader_image_version` (`3.3.0`). `reward.json` gets `grader_version_major`, `grader_version_minor` and `grader_version_patch` as integers, because Harbor rejects any non-numeric value in `reward.json` (`VerifierOutputParseError`). The image reference cannot carry its own digest; the digest is recorded at push time (`push.sh` prints it).

## Build and push

```bash
grader_image/build.sh   # builds and tags locally, runs a no-network smoke test
grader_image/push.sh    # gcloud auth configure-docker + push (needs registry write access)
```

`build.sh` produces three tags for the same image:

- `us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-grader:3` (moving major tag, what tasks reference)
- `us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-grader:3.3.0` (fixed, never re-pushed)
- `sast-grader:3` (local alias)

`push.sh` pushes the fixed tag first, then moves `:3` to it, and prints the repo digest.

## Tag policy

- `:3` moves for compatible grader fixes: bug fixes, robustness, extra output keys, anything that keeps the ground-truth schema and the meaning of existing scores. Bump `VERSION` (patch, or minor together with `GRADER_VERSION` in grade.py), rebuild, push. Every task built afterwards, and every regrade, picks up the fix without touching task files.
- A breaking change (new required ground-truth fields, a different reward definition, renamed `reward.json` keys) gets a new major: `VERSION` `4.0.0`, tag `:4`, and tasks move to it by changing one `FROM` line in `tests/Dockerfile`. `:3` stays where it was, so old tasks keep grading the old way.
- Fixed tags (`:3.3.0`) are never overwritten. To pin a task hard, use `FROM .../sast-grader:3.3.0@sha256:<digest>`.

Caveat: a moving tag only helps if the platform rebuilds the verifier image (or re-pulls the tag) after it moves. Harbor's local docker build does not use `--pull`, so a host that already has an older `:3` keeps using it until that image is removed or replaced. See the open questions in `pilot_v4/README.md`.

## Local fallback (no registry access)

Harbor's docker environment builds `tests/Dockerfile` without `--pull`, so an image present locally under the exact name and tag satisfies `FROM .../sast-grader:3` without registry credentials. `build.sh` already creates that tag. On a machine that only has the image from elsewhere (a `docker save` tarball, or the short local tag):

```bash
docker load -i sast-grader_3.tar           # if shipped as a tarball
docker tag sast-grader:3 us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-grader:3
```

The same trick works for the agent image's `FROM .../sast-tools:0.5.0@sha256:1cfbcb...`: with Docker Desktop's containerd image store, `docker load -i handoff/sast-tools_0.5.0_amd64.tar.gz` gives `sast-tools:0.5.0` with image id `sha256:1cfbcb...`, and `docker tag sast-tools:0.5.0 us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-tools:0.5.0` lets the digest-pinned `FROM` build without a pull (checked 2026-11-06).

## Regrade

Because the grader lives in the verifier image and the verifier sees only declared artifacts, a finished job can be re-scored with a newer grader without rerunning any scanner:

```bash
grader_image/build.sh                     # or push.sh, so the platform gets the new :3
harbor job regrade jobs/<job> -p path/to/tasks -e docker
harbor trial regrade jobs/<job>/<trial> -p path/to/task -e docker
```

Each regraded trial records the grader that scored it (`grader_version_*` in `reward.json`, `grader_image_version` in `grading_detail.json`). Harbor 0.25 constructs the agent environment object even for a regrade, so variables templated in `[environment.env]` (e.g. `PROMPTFOO_TOKEN`) must exist on the host, even if empty. A trial whose agent produced no SARIF cannot be regraded when the artifact is declared as the file; see `pilot_v4/README.md`.
