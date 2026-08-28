#!/usr/bin/env bash
# fleet-sweep.sh — the weekly fleet health sweep's mechanical gatherer.
#
# Emits one sectioned report over the machine's tool estate: binary
# provenance, shape-corpus version lag, gomutant findings-store health,
# stipulator check verdicts, and pew store freshness. The script only
# GATHERS; judgment and filing belong to the sweep pipeline reading the
# report (docs/fleet-sweep.md).
#
# Health vocabulary is three-valued: a fact, a red fact, or NOT
# MEASURED — a missing tool, a refused lock, or a timed-out command is
# never expressible as an estate fact, and the judge never files it as
# one. A sweep that cannot run at all ABORTS (exit 2, no trailer); a
# sweep the machine's quiet window defers DEFERS (exit 3, deferred
# trailer); only a completed sweep prints the "sweep complete" trailer
# the runner requires before judging.
#
# Caps are visible, not silent: the estate lists below ARE the estate
# definition, the report prints them, and every per-repo loop reports
# an absent repo as ABSENT rather than skipping it.

set -uo pipefail

GL=~/repos/github.com/greatliontech

# Repos whose installed binary must match the repo HEAD.
BINARY_REPOS=(gomutant pew stipulator)
# Repos consuming the gofresh shape corpus (version-lag check).
CORPUS_CONSUMERS=(gomutant stipulator pew)
# Repos carrying gomutant findings stores.
FINDINGS_REPOS=(tugboat gomutant gofresh stipulator pew pando pb protodb ocifs gmdb)
# Repos with stipulator estates: check runs where bindings exist and
# reports adoption-incomplete where only a manifest does.
STIPULATOR_REPOS=(stipulator gofresh gomutant tugboat ocifs pando pb)
# Repos with pew stores; per-repo standing vouches below.
PEW_REPOS=(tugboat protodb)

# Per-repo standing pew arguments: the reviewed vouch set AND the
# store's variant label. tugboat's vouches are the audited list from
# its CLAUDE.md "Standing vouch" section (per-entry provenance there;
# that section points back here — keep both in step until a repo-level
# vouch source lands: pew docs/issues/repo-level-vouch-source.md) and
# its store is unlabeled. protodb's store records under the
# pebble-dragonboat label — statusing without it reads every recorded
# arm as unrecorded, a false red the second production run's judge
# caught — and has no assessed vouch set yet (unverifiable rows are
# expected and self-announcing until one is recorded).
pew_args() {
  case "$1" in
    tugboat) printf '%s\n' \
      --vouch github.com/zeebo/xxh3:key \
      --vouch pgregory.net/rapid:anyRuneGen \
      --vouch go.uber.org/goleak:_osStderr \
      --vouch google.golang.org/grpc:globalDialOptions \
      --vouch google.golang.org/grpc:globalPerTargetDialOptions \
      --vouch google.golang.org/grpc:globalServerOptions ;;
    protodb) printf '%s\n' --label pebble-dragonboat ;;
    *) ;;
  esac
}

# Preflight: a missing tool aborts the whole sweep — it must never
# masquerade as estate red.
for tool in mlock gomutant stipulator pew go git du; do
  if ! command -v "$tool" > /dev/null 2>&1; then
    echo "SWEEP ABORTED: required tool '$tool' not on PATH ($PATH)"
    exit 2
  fi
done

# Quiet gate: a wanted-quiet window at start defers the whole sweep;
# a refusal mid-sweep still marks its own section NOT MEASURED.
if ! mlock run true > /dev/null 2>&1; then
  echo "== sweep deferred =="
  echo "machine quiet-wanted at start; sweep defers to the next timer fire"
  date -Is
  exit 3
fi

# runlocked <budget-seconds> <cmd...>: the machine lock outside the
# budget (lock WAITS are legitimate and uncapped; only the command's
# own runtime is budgeted). Three-valued result via rc: 124 = budget
# exceeded, 3 = lock refused — mlock's quiet-refusal exit status (see
# ~/.local/bin/mlock; if mlock ever repurposes rc 3 this mapping and
# the NOT MEASURED lines it feeds must move with it) — else the
# command's own rc.
runlocked() {
  local budget=$1
  shift
  mlock run timeout "$budget" "$@"
}

SWEEP_TMPS=()
cleanup_tmps() { [ ${#SWEEP_TMPS[@]} -gt 0 ] && rm -f "${SWEEP_TMPS[@]}"; }
trap cleanup_tmps EXIT

mktemp_tracked() {
  local t
  t=$(mktemp)
  SWEEP_TMPS+=("$t")
  echo "$t"
}

section() { printf '\n== %s ==\n' "$1"; }

echo "fleet sweep report"
date -Is
echo "estate: binaries=(${BINARY_REPOS[*]}) corpus=(${CORPUS_CONSUMERS[*]}) findings=(${FINDINGS_REPOS[*]}) stipulator=(${STIPULATOR_REPOS[*]}) pew=(${PEW_REPOS[*]})"

section "binary provenance (installed vs repo HEAD)"
for r in "${BINARY_REPOS[@]}"; do
  [ -d "$GL/$r" ] || { echo "$r: REPO ABSENT"; continue; }
  bin=~/go/bin/$r
  if [ ! -x "$bin" ]; then
    echo "$r: NO BINARY installed"
    continue
  fi
  rev=$(go version -m "$bin" 2>/dev/null | grep -o 'vcs.revision=[0-9a-f]*' | head -1 | cut -d= -f2 | cut -c1-12)
  mod=$(go version -m "$bin" 2>/dev/null | grep -o 'vcs.modified=[a-z]*' | head -1 | cut -d= -f2)
  # The fact the check wants is "does the binary carry the latest
  # BUILD INPUTS", not "the latest commit": docs commits — including
  # the sweep's own filings — move HEAD weekly, and a HEAD comparison
  # manufactures the skew it then files, forever. Compare against the
  # last commit touching anything outside docs/ and *.md.
  built=$(git -C "$GL/$r" log -1 --format=%h --abbrev=12 -- . ':(exclude)docs' ':(exclude)*.md' 2>/dev/null)
  if [ -z "$rev" ]; then
    echo "$r: NO VCS STAMP in binary (built with -buildvcs=off?) last-build-input=$built"
    continue
  fi
  if [ -z "$built" ]; then
    echo "$r: NO BUILD-INPUT COMMIT found (docs-only history?) binary=$rev"
    continue
  fi
  state=match
  if ! git -C "$GL/$r" merge-base --is-ancestor "$rev" HEAD 2>/dev/null; then
    # A binary from an unmerged branch carries code HEAD never saw.
    state="SKEW (off-history build)"
  elif [ "$rev" != "$built" ] && ! git -C "$GL/$r" merge-base --is-ancestor "$built" "$rev" 2>/dev/null; then
    state=SKEW
  fi
  [ "$mod" = "true" ] && state="$state DIRTY-BUILD"
  echo "$r: binary=$rev last-build-input=$built $state"
done

section "shape-corpus version lag (pinned gofresh vs latest tag)"
# CI mints release tags remotely; the local clone may lag them, so the
# authority is the remote. The fallback to local tags is stated in the
# report — a silently local answer re-opens the inversion the remote
# query exists to close.
source=remote
latest=$(git -C "$GL/gofresh" ls-remote --tags origin 2>/dev/null | grep -o 'refs/tags/v[0-9.]*$' | sed 's|refs/tags/||' | sort -V | tail -1)
if [ -z "$latest" ]; then
  source="LOCAL FALLBACK (offline?) — may lag the true latest"
  latest=$(git -C "$GL/gofresh" tag --sort=-v:refname 2>/dev/null | head -1)
fi
echo "gofresh latest tag: $latest (source: $source)"
for r in "${CORPUS_CONSUMERS[@]}"; do
  [ -d "$GL/$r" ] || { echo "$r: REPO ABSENT"; continue; }
  pinned=$(grep -o 'github.com/greatliontech/gofresh v[0-9.]*' "$GL/$r/go.mod" 2>/dev/null | awk '{print $2}')
  if [ -z "$pinned" ]; then
    echo "$r: NO PIN found in go.mod"
    continue
  fi
  state=current
  [ "$pinned" != "$latest" ] && state=LAG
  echo "$r: pinned=$pinned $state"
done

section "gomutant findings stores (size + record summary)"
# Inspection cost on large stores is a LIVE tracked fault (train chunk
# 110: findings-inspection-cost) — a budget-exceeded inspection is a
# sweep fact to report, never an estate red.
for r in "${FINDINGS_REPOS[@]}"; do
  [ -d "$GL/$r" ] || { echo "$r: REPO ABSENT"; continue; }
  store="$GL/$r/.gomutant"
  [ -d "$store" ] || { echo "$r: no findings store"; continue; }
  size=$(du -sh "$store" 2>/dev/null | cut -f1)
  out=$(cd "$GL/$r" && runlocked 30 gomutant findings 2>&1)
  rc=$?
  case $rc in
    0) summary=$(echo "$out" | tail -3 | tr '\n' ' ') ;;
    124) summary="NOT MEASURED: inspection exceeded 30s (train chunk 110 tracks inspection cost)" ;;
    3) summary="NOT MEASURED: machine lock refused (quiet wanted)" ;;
    *) summary="TOOL ERROR: $(echo "$out" | tail -1)" ;;
  esac
  echo "$r: $size — $summary"
done

section "stipulator check verdicts"
for r in "${STIPULATOR_REPOS[@]}"; do
  [ -d "$GL/$r" ] || { echo "$r: REPO ABSENT"; continue; }
  est="$GL/$r/.stipulator"
  [ -d "$est" ] || { echo "$r: no estate"; continue; }
  if [ ! -d "$est/bindings" ] || [ -z "$(ls -A "$est/bindings" 2>/dev/null)" ]; then
    echo "$r: adoption incomplete (manifest only — train chunk 134)"
    continue
  fi
  tmp=$(mktemp_tracked)
  (cd "$GL/$r" && runlocked 3600 stipulator check) > "$tmp" 2>&1
  rc=$?
  case $rc in
    124) verdict="NOT MEASURED: check exceeded 3600s budget" ;;
    3) verdict="NOT MEASURED: machine lock refused (quiet wanted)" ;;
    *)
      verdict=$(grep -E '^check: (pass|fail)' "$tmp" | tail -1)
      # rc-nonzero with no verdict line is ambiguous between a tool
      # malfunction and an estate fault — ambiguity is not a fact.
      [ -z "$verdict" ] && verdict="NOT MEASURED: no verdict (rc=$rc) — last: $(tail -1 "$tmp")"
      ;;
  esac
  if [ -n "${SWEEP_ROWS_DIR:-}" ]; then
    grep -E '^ *(violation:|stale +REQ|uncovered +REQ)' "$tmp" > "$SWEEP_ROWS_DIR/check-$r.txt" 2>/dev/null || true
  fi
  total=$(grep -cE '^ *(violation:|stale +REQ|uncovered +REQ)' "$tmp")
  # head closing the pipe early SIGPIPEs grep under pipefail and its
  # stderr complaint would land inside the report — cap after the
  # capture instead.
  rows=$(grep -E '^ *(violation:|stale +REQ|uncovered +REQ)' "$tmp" 2>/dev/null || true)
  detail=$(printf '%s' "$rows" | head -6 | tr '\n' ';')
  shown=$total
  [ "$total" -gt 6 ] && shown="6 of $total"
  echo "$r: $verdict — showing $shown rows: $detail"
  rm -f "$tmp"
done

section "pew store freshness"
for r in "${PEW_REPOS[@]}"; do
  [ -d "$GL/$r" ] || { echo "$r: REPO ABSENT"; continue; }
  mapfile -t pewargs < <(pew_args "$r")
  case " ${pewargs[*]-} " in
    *" --vouch "*) : ;;
    *) echo "$r: NOTE — no assessed vouch set; unverifiable rows expected until one is recorded" ;;
  esac
  report=$(mktemp_tracked)
  (cd "$GL/$r" && runlocked 3600 pew status ${pewargs[@]+"${pewargs[@]}"} ./...) > "$report" 2>&1
  rc=$?
  case $rc in
    124) echo "$r: NOT MEASURED: status exceeded 3600s budget" ;;
    3) echo "$r: NOT MEASURED: machine lock refused (quiet wanted)" ;;
    *)
      counts=$(grep -E '^(valid|stale|unverifiable|unrecorded)' "$report" | awk '{print $1}' | sort | uniq -c | sort -rn | tr '\n' ' ')
      nonvalid=$(grep -E '^(stale|unverifiable|unrecorded)' "$report" 2>/dev/null || true)
      if [ -n "${SWEEP_ROWS_DIR:-}" ]; then
        # Same empty representation as the check tee-out: a zero-byte
        # file, never a lone blank line.
        printf '%s' "$nonvalid" > "$SWEEP_ROWS_DIR/pew-$r.txt"
        [ -s "$SWEEP_ROWS_DIR/pew-$r.txt" ] && printf '\n' >> "$SWEEP_ROWS_DIR/pew-$r.txt"
      fi
      total=$(printf '%s' "$nonvalid" | grep -c . || true)
      shown=$total
      [ "$total" -gt 15 ] && shown="15 of $total"
      echo "$r: args: ${pewargs[*]:-none (unlabeled, no vouches)} — verdict counts: $counts (showing $shown non-valid rows)"
      printf '%s\n' "$nonvalid" | head -15
      ;;
  esac
  rm -f "$report"
done

section "parked filings pending"
pending=0
for f in ~/.local/state/fleet-sweep/parked/*; do
  [ -e "$f" ] || continue
  # A drained file is history, not pending work.
  head -1 "$f" 2>/dev/null | grep -q '^drained ' && continue
  basename "$f"
  pending=$((pending + 1))
done
[ "$pending" -eq 0 ] && echo "none"

section "sweep complete"
# The trailer attests the sweep REACHED ITS END; per-section health
# stays three-valued (the runner appends the not-measured tally so a
# mostly unmeasured sweep cannot read as a quiet green).
date -Is
