#!/usr/bin/env bash
# fleet-sweep-run.sh — the systemd timer's entry point: run the
# mechanical gatherer, persist the dated report, invoke the headless
# judge, then COMMIT the judge's filings itself. The trust boundary is
# structural, not prose: the judge's tool surface is write-only
# (Read/Glob/Grep/Write/Edit — no shell), and this wrapper owns every
# git operation, pathspec-scoped to docs/issues paths, so the judge
# cannot push, run commands, or commit at all. The report survives on
# disk regardless of the judge's outcome — any session can judge a
# waiting report by hand.

set -uo pipefail

GL=~/repos/github.com/greatliontech
ESTATE_REPOS=(gofresh gomutant stipulator pew tugboat pando pb protodb ocifs gmdb)

STATE=~/.local/state/fleet-sweep
mkdir -p "$STATE/parked"
stamp=$(date +%F-%H%M)
report="$STATE/report-$stamp.txt"
judgelog="$STATE/judge-$stamp.log"

prejudge=""
cleanup() { [ -n "$prejudge" ] && rm -rf "$prejudge"; }
trap cleanup EXIT

rowsdir="$STATE/report-$stamp.rows"
mkdir -p "$rowsdir"
SWEEP_ROWS_DIR="$rowsdir" ~/repos/github.com/greatliontech/gofresh/scripts/fleet-sweep.sh > "$report" 2>&1
rc=$?

# Reports and judge logs are process evidence with a bounded shelf
# life; defects they surface live on as issue docs. Keep a quarter.
find "$STATE" -name 'report-*.txt' -mtime +90 -delete
find "$STATE" -name 'judge-*.log' -mtime +90 -delete
find "$STATE" -maxdepth 1 -name 'report-*.rows' -mtime +90 -exec rm -rf {} +

if [ $rc -eq 3 ]; then
  echo "sweep deferred (quiet-wanted); no judge run $(date -Is)" >> "$judgelog"
  rmdir "$rowsdir" 2>/dev/null || true
  exit 0
fi
if [ $rc -ne 0 ] || ! grep -q '^== sweep complete ==' "$report"; then
  echo "sweep FAILED or incomplete (rc=$rc); no judge run — report held for hand judgment $(date -Is)" >> "$judgelog"
  rmdir "$rowsdir" 2>/dev/null || true
  exit 1
fi
echo "not-measured lines: $(grep -c 'NOT MEASURED' "$report" || true)" >> "$report"

# Pre-judge snapshots: which repos' issue indexes carry in-flight
# changes (the judge parks those rows in the state dir instead of
# touching the index), and which docs/issues files are ALREADY
# untracked — the commit walk below commits only files that appear
# AFTER the judge, so a foreign parked doc is never swept into a
# sweep commit (the first production run did exactly that).
dirty_indexes=""
dirty_docs=""
prejudge=$(mktemp -d)
for r in "${ESTATE_REPOS[@]}"; do
  [ -d "$GL/$r" ] || continue
  if ! git -C "$GL/$r" diff --quiet HEAD -- docs/issues/README.md 2>/dev/null; then
    dirty_indexes="$dirty_indexes $r"
  fi
  git -C "$GL/$r" ls-files --others --exclude-standard docs/issues/ 2>/dev/null > "$prejudge/$r" || true
  git -C "$GL/$r" diff --name-only HEAD -- docs/issues/ 2>/dev/null > "$prejudge/$r.dirty" || true
  while IFS= read -r f; do
    # The index has its own list and rule; dirty_docs carries DOCS.
    [ -n "$f" ] && [ "$f" != "docs/issues/README.md" ] && dirty_docs="$dirty_docs $r/$f"
  done < "$prejudge/$r.dirty"
  git -C "$GL/$r" diff --name-only HEAD -- ':(exclude)docs/issues' 2>/dev/null > "$prejudge/$r.outside" || true
  git -C "$GL/$r" ls-files --others --exclude-standard -- ':(exclude)docs/issues' 2>/dev/null > "$prejudge/$r.outside-new" || true
done

prompt="You are the weekly fleet health sweep judge. Read the sweep
report at $report and the runbook at
$STATE/runbook.md, then disposition every RED fact per
the runbook's filing doctrine: write (do not commit — the wrapper
commits) an issue doc under the owning repo's docs/issues/ with a
Lands: line per that repo's own conventions — for the tool repos, the
cross-tool train plan at $STATE/cross-tool-train.md (a read copy)
is the register; elsewhere prefer, in strict order, a chunk of that
repo's active plan, a checkable condition (a repo's next change-set
gate that forces the fact's diagnosis is a legitimate condition), and
only then 'user decision'. Append the index row to the repo's
docs/issues/README.md UNLESS the repo is in this dirty-index list:
[${dirty_indexes:-none}] — for those, write the row to
$STATE/parked/<repo>-rows-$stamp.md instead and say so in your reply.
Lines marked NOT MEASURED, DEFERRED, or NOTE are never red facts —
never file them. Dedup is a DUTY WITH A METHOD: for every red fact
your reply carries a scanned: line naming the candidate docs you
considered in the owning repo; a new doc whose rows overlap an
existing doc is forbidden — widen the existing doc, or state row
disjointness explicitly — and a filing never mints a second Lands:
trigger for work another doc already schedules (adopt or retarget
that trigger instead) — and a Lands: change rewrites the owning repo's
index row in the same edit, because the row is what triage reads. The
full uncapped row lists behind every capped section are at $rowsdir/
— set claims (which rows a doc covers, what the remainder is) are
made from those files, never from a capped section. These doc paths
are carrying someone's in-flight changes right now:
[${dirty_docs:-none}] — if the doc you would widen is among them,
write your addition to $STATE/parked/<repo>-<docname>-$stamp.md
instead and say so in your reply; nothing you write may land inside a
foreign uncommitted change set. EVERY parked file's first line is
'Target: <repo>/docs/issues/<file>' — the parked file is the sole
carrier of its work across weeks and must say what it is for; the
drain rule reads that line, never the filename. If every section is green,
reply 'judged green $stamp' and write nothing. The parked directory drains
GENERICALLY: for each file the report's 'parked filings pending'
section lists, read its 'Target:' first line, and if that target is
now clean — the index when the repo is not in the dirty-index list, a
doc when it is not in the dirty-docs list — apply it and overwrite
the parked file with the single line 'drained $stamp'; a target still
dirty stays parked, and a parked file without a Target: line gets one
added from its content before anything else."

# The judge's write surface is bounded to exactly what filing needs:
# the state dir, each estate repo's docs/issues, and the runbook and
# train plan it reads. A hostile string in the report can then steer
# at worst a wrong filing inside docs/issues — which the commit walk
# scopes and the weekly review reads — never a write elsewhere.
cp "$GL/gofresh/docs/fleet-sweep.md" "$STATE/runbook.md" || { echo "runbook copy failed; a stale doctrine must not judge $(date -Is)" >> "$judgelog"; exit 1; }
cp "$GL/gofresh/docs/plans/cross-tool-train.md" "$STATE/cross-tool-train.md" || { echo "train-plan copy failed; a stale register must not slot $(date -Is)" >> "$judgelog"; exit 1; }
adddirs=(--add-dir "$STATE")
for r in "${ESTATE_REPOS[@]}"; do
  [ -d "$GL/$r/docs/issues" ] && adddirs+=(--add-dir "$GL/$r/docs/issues")
done
cd "$STATE"
timeout 1800 claude -p "$prompt" \
  --allowedTools "Read,Glob,Grep,Write,Edit" \
  "${adddirs[@]}" \
  >> "$judgelog" 2>&1
echo "judge rc=$? $(date -Is)" >> "$judgelog"

# The wrapper owns the commits: per repo, pathspec-scoped to new
# docs/issues files plus the index IFF the index was clean pre-judge —
# a filing never mixes into someone else's change set, and nothing the
# judge wrote is left silently uncommitted in a tree.
for r in "${ESTATE_REPOS[@]}"; do
  [ -d "$GL/$r/docs/issues" ] || continue
  mapfile -t newdocs < <(git -C "$GL/$r" ls-files --others --exclude-standard docs/issues/ 2>/dev/null | grep -vxF -f "$prejudge/$r" || true)
  paths=("${newdocs[@]}")
  # Tracked docs/issues files the judge modified THAT WERE CLEAN
  # pre-judge join the commit; pre-dirty files are skipped LOUDLY —
  # nothing is silently uncommitted, nothing foreign is swept.
  mapfile -t nowdirty < <(git -C "$GL/$r" diff --name-only HEAD -- docs/issues/ 2>/dev/null || true)
  skipped=""
  for f in "${nowdirty[@]}"; do
    case "$f" in docs/issues/README.md) continue ;; esac
    if grep -qxF "$f" "$prejudge/$r.dirty"; then
      skipped="$skipped $f"
      continue
    fi
    if [ ! -e "$GL/$r/$f" ]; then
      # Nothing authorizes the sweep to DELETE an issue doc.
      echo "REFUSING a deletion in $r: $f vanished during the judge window; left uncommitted" >> "$judgelog"
      continue
    fi
    paths+=("$f")
  done
  case " $dirty_indexes " in
    *" $r "*) : ;;
    *)
      if ! git -C "$GL/$r" diff --quiet HEAD -- docs/issues/README.md 2>/dev/null; then
        paths+=(docs/issues/README.md)
      fi
      ;;
  esac
  # Out-of-scope guard: the judge may only touch docs/issues; a NEW
  # modification elsewhere in the repo since the pre-judge snapshot
  # voids this repo's commit and is reported loudly.
  if ! diff -q <(git -C "$GL/$r" diff --name-only HEAD -- ':(exclude)docs/issues' 2>/dev/null) "$prejudge/$r.outside" > /dev/null 2>&1 ||
     ! diff -q <(git -C "$GL/$r" ls-files --others --exclude-standard -- ':(exclude)docs/issues' 2>/dev/null) "$prejudge/$r.outside-new" > /dev/null 2>&1; then
    [ -n "$skipped" ] && echo "skipped (pre-dirty, stays with its own change set) in $r:$skipped" >> "$judgelog"
    echo "REFUSED commit in $r: the outside-docs/issues state changed (either direction — a foreign edit or revert during the judge window, or an out-of-scope write); filings here stay uncommitted and listed above" >> "$judgelog"
    continue
  fi
  [ -n "$skipped" ] && echo "skipped (pre-dirty, stays with its own change set) in $r:$skipped" >> "$judgelog"
  [ ${#paths[@]} -eq 0 ] && continue
  git -C "$GL/$r" add -- "${paths[@]}" &&
    git -C "$GL/$r" commit -m "docs(sweep): weekly fleet health filings $stamp" -- "${paths[@]}" \
      >> "$judgelog" 2>&1
  echo "committed in $r: ${paths[*]}" >> "$judgelog"
done
