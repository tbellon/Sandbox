#!/usr/bin/env bash
# verify.sh - deterministic merge verification runner.
#
#   verify.sh --staged                 fast pre-commit path (secret scan on the index)
#   verify.sh --range <base> <head>    what a change introduces (base may be "auto")
#   verify.sh --full                   whole-history / whole-tree baseline
#   verify.sh --write-baseline         record today's knip findings and osv-scanner
#                                      advisories as a baseline (never runs gitleaks or jscpd)
#
# Output contract: one "MODE ..." line, one "CHECK <name> <STATUS> <reason>" line
# per check (fixed order: gitleaks, knip, jscpd, osv-scanner), then
# "VERDICT READY" or "VERDICT NOT READY".
# --write-baseline prints "MODE write-baseline" and one "BASELINE <tool> <WROTE|UNCHANGED|
# SKIPPED|REMOVED> <detail>" line per tool instead; every failure there is exit 2.
# Exit codes: 0 READY, 1 NOT READY, 2 usage or environment error.
# Statuses: PASS, FAIL, SKIPPED (check does not apply, reason stated),
# MISSING-TOOL (an applicable tool is absent). There is no bypass switch:
# a check that did not run is never reported as passing.
set -euo pipefail

export NO_COLOR=1

usage() {
  cat >&2 <<'EOF'
usage: verify.sh --staged
       verify.sh --range <base|auto> <head>
       verify.sh --full
       verify.sh --write-baseline
exit codes: 0 READY, 1 NOT READY, 2 usage error
EOF
  exit 2
}

MODE=""
BASE_ARG=""
HEAD_ARG=""
case "${1:-}" in
  --staged) [ $# -eq 1 ] || usage; MODE=staged ;;
  --range)  [ $# -eq 3 ] || usage; MODE=range; BASE_ARG=$2; HEAD_ARG=$3 ;;
  --full)   [ $# -eq 1 ] || usage; MODE=full ;;
  --write-baseline) [ $# -eq 1 ] || usage; MODE=write-baseline ;;
  *) usage ;;
esac

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "verify.sh: not inside a git repository" >&2; exit 2; }
cd "$ROOT"

OUT=${VERIFY_OUT:-.verify-out}
case "$OUT" in /*) ;; *) OUT="$ROOT/$OUT" ;; esac
mkdir -p "$OUT"
OUT_DISP=${OUT#"$ROOT"/}
# Remove only this script's own artefacts from a previous run, so stale evidence is never read.
for f in gitleaks.json gitleaks.log osv.json osv.err osv-findings.txt knip.json knip.err \
         knip-roots.txt knip-new.txt osv-baseline.json osv-baseline.err osv-baseline-scan.toml \
         osv-baseline-next.toml osv-baseline-ids.txt osv-baseline-paths.txt osv-verify.json \
         osv-verify.err osv-verify-ids.txt osv-verify-paths.txt jscpd.ai.txt jscpd.err; do
  rm -f -- "$OUT/$f"
done
rm -f -- "$OUT"/knip-*.json "$OUT"/knip-*.err
rm -rf -- "$OUT/jscpd"

# ------------------------------------------------------------ python3 helper
# One stdlib-only program with sub-commands, so the knip key builder is shared by the
# check and by --write-baseline and the two can never drift apart.
IFS= read -r -d '' HELPER_PY <<'PYHELPER' || true
import datetime, json, os, re, sys

BEGIN = "# BEGIN verify-baseline"
END = "# END verify-baseline"


def jload(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def keys_for(args):
    keys = set()
    for i in range(0, len(args), 2):
        root, path = args[i], args[i + 1]
        d = jload(path)
        issues = d.get("issues", []) if isinstance(d, dict) else []
        for it in issues:
            f = str(it.get("file", "")).replace("\\", "/")
            for typ, items in it.items():
                if not isinstance(items, list):
                    continue
                for item in items:
                    if typ == "files":
                        sym = f
                    elif isinstance(item, dict):
                        n = str(item.get("name", ""))
                        ns = item.get("namespace")
                        sym = "%s.%s" % (ns, n) if ns else n
                    elif isinstance(item, list):
                        sym = "+".join(sorted(str(x.get("name", "")) if isinstance(x, dict) else str(x) for x in item))
                    else:
                        sym = str(item)
                    keys.add("%s|%s|%s|%s" % (root, typ, f, sym))
    return sorted(keys)


def load_baseline(path):
    try:
        d = jload(path)
    except Exception:
        return None, "not valid JSON"
    if not isinstance(d, dict):
        return None, "top level is not an object"
    k = d.get("keys")
    if not isinstance(k, list):
        return None, "no keys list"
    if not all(isinstance(x, str) for x in k):
        return None, "keys is not a list of strings"
    return d, None


def emit_bytes(text):
    sys.stdout.buffer.write(os.fsencode(text))


def cmd_roots():
    files = [os.fsdecode(p) for p in sys.stdin.buffer.read().split(b"\0") if p]

    def out(status, roots=()):
        emit_bytes(status + "\n" + "".join(r + "\n" for r in roots))
        sys.exit(0)

    cfg = None
    if os.path.lexists(".verify.json"):
        try:
            cfg = jload(".verify.json")
        except Exception:
            out("ERR not valid JSON")
        if not isinstance(cfg, dict):
            out("ERR top level is not an object")
    if cfg is not None and "knipRoots" in cfg:
        kr = cfg["knipRoots"]
        if not isinstance(kr, list) or not all(isinstance(x, str) for x in kr):
            out("ERR knipRoots must be a list of strings")
        if not kr:
            out("DISABLED")
        real = os.path.realpath(".")
        roots = set()
        for e in kr:
            n = e
            if n.strip() == "" or n.startswith("/") or "\\" in n or "\n" in n or ".." in n.split("/"):
                out("ERR knipRoots entry %r must be a relative path without .." % e)
            while n.startswith("./"):
                n = n[2:]
            n = n.rstrip("/") or "."
            if not os.path.isfile(os.path.join(n, "package.json")):
                out("ERR knipRoots entry %r has no package.json" % e)
            rp = os.path.realpath(n)
            if rp != real and not rp.startswith(real + os.sep):
                out("ERR knipRoots entry %r resolves outside the repository" % e)
            roots.add(n)
        out("OK", sorted(roots, key=lambda r: (r != ".", r)))
    roots = set()
    for p in files:
        parts = p.split("/")
        if parts[-1] != "package.json" or "node_modules" in parts[:-1]:
            continue
        r = "/".join(parts[:-1]) or "."
        if "\n" in r:
            out("ERR a package.json directory name contains a newline")
        roots.add(r)
    if not roots:
        out("NONE")
    out("OK", sorted(roots, key=lambda r: (r != ".", r)))


def cmd_declared():
    try:
        d = jload("package.json")
    except Exception:
        print("invalid")
        return
    ks = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    print("yes" if isinstance(d, dict) and any(d.get(k) for k in ks) else "no")


def cmd_summary(path):
    d = jload(path)
    issues = d.get("issues", []) if isinstance(d, dict) else []
    tot = {}
    for it in issues:
        for k, v in it.items():
            if isinstance(v, list):
                tot[k] = tot.get(k, 0) + len(v)
    n = sum(tot.values())
    files = tot.get("files", 0)
    exports = sum(tot.get(k, 0) for k in ("exports", "types", "nsExports", "nsTypes", "enumMembers", "namespaceMembers", "duplicates"))
    deps = sum(tot.get(k, 0) for k in ("dependencies", "devDependencies", "optionalPeerDependencies", "unlisted", "unresolved", "binaries", "catalog", "catalogReferences"))
    if n == 0:
        sys.exit(3)
    print("%d finding(s) (unused files %d, exports %d, dependencies %d)" % (n, files, exports, deps))


def cmd_gate(base, newfile, pairs):
    d, _ = load_baseline(base)
    cur = set(keys_for(pairs))
    bset = set(d["keys"])
    new = sorted(cur - bset)
    if new:
        with open(newfile, "w", encoding="utf-8") as fh:
            fh.write("".join(k + "\n" for k in new))
    print(len(new))
    print(len(bset))
    print(len(bset - cur))
    print(new[0] if new else "")


def cmd_knip_next(out, existing, tool, today, pairs):
    keys = keys_for(pairs)
    if os.path.exists(existing):
        d, _ = load_baseline(existing)
        if d is not None and d["keys"] == keys and d.get("tool") == tool:
            with open(existing, "rb") as fh:
                data = fh.read()
            with open(out, "wb") as fh:
                fh.write(data)
            print(len(keys))
            return
    obj = {"generated": today, "tool": tool, "keys": keys}
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")
    print(len(keys))


def split_block(text):
    lines = text.splitlines(True)
    b = [i for i, l in enumerate(lines) if l.strip() == BEGIN]
    e = [i for i, l in enumerate(lines) if l.strip() == END]
    if not b and not e:
        return lines, None, None
    if len(b) != 1 or len(e) != 1 or b[0] > e[0]:
        raise ValueError("unbalanced or duplicated verify-baseline markers (expected one BEGIN then one END)")
    return lines, b[0], e[0]


def read_text(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def cmd_osv_prep(existing, stripped):
    lines, b, e = split_block(read_text(existing))
    keep = lines if b is None else lines[:b] + lines[e + 1:]
    with open(stripped, "w", encoding="utf-8", newline="") as fh:
        fh.write("".join(keep))
    print("block" if b is not None else "noblock")


def cmd_osv_collect(path, root, idfile, pathfile):
    d = jload(path)
    ids, paths = set(), set()
    for r in d.get("results", []) or []:
        src = (r.get("source", {}) or {}).get("path", "")
        has = False
        for p in r.get("packages", []) or []:
            for v in p.get("vulnerabilities", []) or []:
                if v.get("id"):
                    ids.add(str(v["id"]))
                    has = True
        if has and src:
            rel = os.path.relpath(src, root) if os.path.isabs(src) else src
            paths.add(rel.replace(os.sep, "/"))
    with open(idfile, "w", encoding="utf-8") as fh:
        fh.write("".join(i + "\n" for i in sorted(ids)))
    with open(pathfile, "w", encoding="utf-8") as fh:
        fh.write("".join(p + "\n" for p in sorted(paths)))
    print(len(ids))
    if not ids:
        sys.exit(3)


def cmd_osv_next(existing, out, idfile, today, expiry):
    with open(idfile, encoding="utf-8") as fh:
        ids = sorted({l.strip() for l in fh if l.strip()})
    have = existing != "-" and os.path.exists(existing)
    text = read_text(existing) if have else ""
    lines, b, e = split_block(text) if have else ([], None, None)
    outside = lines if b is None else lines[:b] + lines[e + 1:]
    outside_ids = set(re.findall(r'^\s*id\s*=\s*"([^"]+)"', "".join(outside), re.M))
    place = sorted(set(ids) - outside_ids)
    skipped = len(set(ids) & outside_ids)
    kept = {}
    if b is not None:
        entries = []
        cur = None
        for l in lines[b + 1:e]:
            if l.strip() == "[[IgnoredVulns]]":
                cur = [l]
                entries.append(cur)
            elif cur is not None:
                cur.append(l)
        for en in entries:
            while en and en[-1].strip() == "":
                en.pop()
            body = "".join(en)
            m = re.search(r'^\s*id\s*=\s*"([^"]+)"', body, re.M)
            if m and re.search(r"^\s*reason\s*=", body, re.M) and re.search(r"^\s*ignoreUntil\s*=", body, re.M):
                kept[m.group(1)] = body if body.endswith("\n") else body + "\n"
    if place:
        parts = []
        for i in place:
            parts.append(kept.get(i) or '[[IgnoredVulns]]\nid = "%s"\nreason = "pre-existing at verify baseline %s; fix before ignoreUntil"\nignoreUntil = %s\n' % (i, today, expiry))
        block = BEGIN + "\n# Managed by verify.sh --write-baseline. Entries expire at ignoreUntil; fix the dependency instead of extending the date.\n\n" + "\n".join(parts) + END + "\n"
        if b is not None:
            new = "".join(lines[:b]) + block + "".join(lines[e + 1:])
        elif text == "":
            new = block
        else:
            new = text + ("" if text.endswith("\n") else "\n") + "\n" + block
        action = "WRITE"
    elif b is None:
        new = text
        action = "NOCHANGE"
    else:
        start = b - 1 if b > 0 and lines[b - 1].strip() == "" else b
        new = "".join(lines[:start]) + "".join(lines[e + 1:])
        action = "DELETE" if new.strip() == "" else "WRITE"
    if action != "DELETE" and have and new == text:
        action = "NOCHANGE"
    if action == "WRITE" and not have and not place:
        action = "NOCHANGE"
    with open(out, "w", encoding="utf-8", newline="") as fh:
        fh.write(new)
    print("%s %d %d" % (action, len(place), skipped))


def cmd_today(days):
    d = datetime.datetime.now(datetime.timezone.utc).date() + datetime.timedelta(days=int(days))
    print(d.isoformat())


a = sys.argv[1:]
cmd = a[0]
try:
    if cmd == "roots":
        cmd_roots()
    elif cmd == "declared":
        cmd_declared()
    elif cmd == "summary":
        cmd_summary(a[1])
    elif cmd == "keys":
        for k in keys_for(a[1:]):
            print(k)
    elif cmd == "check-baseline":
        d, why = load_baseline(a[1])
        if d is None:
            print(why)
            sys.exit(3)
    elif cmd == "gate":
        cmd_gate(a[1], a[2], a[3:])
    elif cmd == "knip-next":
        cmd_knip_next(a[1], a[2], a[3], a[4], a[5:])
    elif cmd == "osv-prep":
        cmd_osv_prep(a[1], a[2])
    elif cmd == "osv-collect":
        cmd_osv_collect(a[1], a[2], a[3], a[4])
    elif cmd == "osv-next":
        cmd_osv_next(a[1], a[2], a[3], a[4], a[5])
    elif cmd == "today":
        cmd_today(a[1] if len(a) > 1 else 0)
    else:
        sys.exit(64)
except ValueError as exc:
    print(exc)
    sys.exit(3)
PYHELPER
hp() { python3 -I -c "$HELPER_PY" "$@"; }

BLOCK=0
HEAD_SHA=""
BASE_SHA=""
MODE_LABEL=$MODE

die2() { echo "verify.sh: $*" >&2; exit 2; }

IS_SHALLOW=false
if [ "$(git rev-parse --is-shallow-repository 2>/dev/null || echo false)" = true ]; then
  IS_SHALLOW=true
fi

# Resolve --range <base|auto> <head> to shas. Head must be the checked-out commit,
# because the working-tree checks (jscpd, knip, osv-scanner) scan the checkout.
resolve_range() {
  local head_in=$HEAD_ARG base_in=$BASE_ARG cur up mb
  HEAD_SHA=$(git rev-parse --verify -q "${head_in}^{commit}" 2>/dev/null) || die2 "cannot resolve head '$head_in'"
  cur=$(git rev-parse --verify -q "HEAD^{commit}" 2>/dev/null) || die2 "repository has no commits"
  [ "$HEAD_SHA" = "$cur" ] || die2 "checkout $head_in first (the working-tree checks scan the checked-out commit)"
  if [ "$base_in" = auto ]; then
    if up=$(git rev-parse -q --verify '@{upstream}^{commit}' 2>/dev/null); then
      base_in=$up
    else
      # No upstream: merge-base with the remote default branch (origin/HEAD, which may be
      # dangling), then origin/main, then origin/master.
      local cand oh found=""
      oh=$(git symbolic-ref -q refs/remotes/origin/HEAD 2>/dev/null || true)
      for cand in "$oh" refs/remotes/origin/main refs/remotes/origin/master; do
        [ -n "$cand" ] || continue
        if mb=$(git merge-base "$cand" HEAD 2>/dev/null); then
          base_in=$mb
          found=yes
          break
        fi
      done
      [ -n "$found" ] || die2 "cannot resolve base; pass --range <base> <head>"
    fi
  fi
  if ! BASE_SHA=$(git rev-parse --verify -q "${base_in}^{commit}" 2>/dev/null); then
    if [ "$IS_SHALLOW" = true ]; then
      die2 "shallow clone: base '$base_in' is not available; use fetch-depth 0 (full history)"
    fi
    die2 "cannot resolve base '$base_in'"
  fi
  MODE_LABEL="range ${BASE_SHA:0:7}..${HEAD_SHA:0:7}"
}

if [ "$MODE" = range ]; then
  resolve_range
fi

# emit <name> <STATUS> <reason>: exactly one CHECK line, reason flattened and capped at 200 chars.
emit() {
  local name=$1 status=$2 reason=${3:-}
  reason=$(printf '%s' "$reason" | tr '\r\n\t' '   ' | sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' | cut -c1-200)
  printf 'CHECK %s %s %s\n' "$name" "$status" "$reason"
  case "$status" in
    FAIL|MISSING-TOOL) BLOCK=1 ;;
  esac
}

# --------------------------------------------------------------------- gitleaks
run_gitleaks() {
  if ! command -v gitleaks >/dev/null 2>&1; then
    emit gitleaks MISSING-TOOL "gitleaks not installed; install the pinned release (see SKILL.md)"
    return 0
  fi
  local args=(git --redact --no-banner --exit-code 2 --report-format json --report-path "$OUT/gitleaks.json")
  if [ -f .gitleaks.toml ]; then
    args+=(-c .gitleaks.toml)
  fi
  local scope
  case "$MODE" in
    staged) args+=(--staged); scope="staged changes" ;;
    range)
      args+=("--log-opts=$BASE_SHA..$HEAD_SHA")
      scope="$(git rev-list --count "$BASE_SHA..$HEAD_SHA" 2>/dev/null || echo '?') commit(s) ${BASE_SHA:0:7}..${HEAD_SHA:0:7}"
      ;;
    *)
      if [ "$IS_SHALLOW" = true ]; then
        scope="shallow history ($(git rev-list --count HEAD 2>/dev/null || echo '?') commits only; fetch full history for a complete scan)"
      else
        scope="full history"
      fi
      ;;
  esac
  local rc=0
  gitleaks "${args[@]}" >"$OUT/gitleaks.log" 2>&1 || rc=$?
  case "$rc" in
    0)
      emit gitleaks PASS "0 findings in $scope"
      ;;
    2)
      local n="" rules=""
      if parsed=$(python3 -I -c '
import json, sys
f = json.load(open(sys.argv[1]))
print(len(f))
print(",".join(sorted({str(x.get("RuleID", "?")) for x in f})))
' "$OUT/gitleaks.json" 2>/dev/null); then
        n=$(printf '%s\n' "$parsed" | sed -n 1p)
        rules=$(printf '%s\n' "$parsed" | sed -n 2p)
      fi
      if [ -n "$n" ]; then
        emit gitleaks FAIL "$n finding(s) in $scope (rules: $rules); see $OUT_DISP/gitleaks.json; rotate the credential before removing it"
      else
        emit gitleaks FAIL "findings in $scope (report unreadable); rotate the credential before removing it"
      fi
      ;;
    *)
      emit gitleaks FAIL "gitleaks error (exit $rc); see $OUT_DISP/gitleaks.log"
      ;;
  esac
}

# ------------------------------------------------------------------------ knip
KNIP_VERSION=6.44.1
KNIP_BASELINE=.verify-baseline/knip.json
KBIN=()
KNIP_TOOL_OK=true
KNIP_RSTATUS=""
KNIP_RNOTE=""
KNIP_ROOTS=""
KF_COUNT=0
KF_ROOT=""
KF_REASON=""
KR_STATE=""
KR_REASON=""
KR_JSON=""
KPAIRS=()

knip_find_tool() {
  if command -v knip >/dev/null 2>&1; then
    KBIN=(knip)
  elif command -v npx >/dev/null 2>&1; then
    KBIN=(npx --yes "knip@$KNIP_VERSION")
  else
    KNIP_TOOL_OK=false
  fi
}

# Sets KNIP_RSTATUS (OK|DISABLED|NONE|ERR), KNIP_RNOTE (error reason) and KNIP_ROOTS
# (one root per line, "." for the repository root; empty unless OK).
knip_load_roots() {
  local raw first
  KNIP_ROOTS=""
  KNIP_RNOTE=""
  if ! raw=$(git ls-files -z | hp roots); then
    raw="ERR cannot list the tracked package.json files"
  fi
  first=${raw%%$'\n'*}
  case "$first" in
    OK) KNIP_RSTATUS=OK ;;
    DISABLED) KNIP_RSTATUS=DISABLED ;;
    NONE) KNIP_RSTATUS=NONE ;;
    *) KNIP_RSTATUS=ERR; KNIP_RNOTE=${first#ERR } ;;
  esac
  case "$raw" in
    *$'\n'*) KNIP_ROOTS=${raw#*$'\n'} ;;
  esac
}

# knip_root_run <root> <NN>: analyse one root (cwd = root). Sets KR_STATE
#   ok0 (exit 0) | ok1 (findings, KR_JSON readable) | fail | missing, and KR_REASON.
# Evidence: root "." keeps the v1 names knip.json/knip.err, other roots use knip-<NN>.json/.err.
knip_root_run() {
  local root=$1 nn=$2 jf ef jd ed declared rc=0 summary=""
  if [ "$root" = . ]; then
    jf="$OUT/knip.json"; ef="$OUT/knip.err"; jd="$OUT_DISP/knip.json"; ed="$OUT_DISP/knip.err"
  else
    jf="$OUT/knip-$nn.json"; ef="$OUT/knip-$nn.err"; jd="$OUT_DISP/knip-$nn.json"; ed="$OUT_DISP/knip-$nn.err"
  fi
  KR_JSON=$jf
  KR_REASON=""
  if [ ! -f "$root/package.json" ]; then
    KR_STATE=fail; KR_REASON="package.json is missing"; return 0
  fi
  declared=$(cd -- "$root" && hp declared 2>/dev/null || echo invalid)
  if [ "$declared" = invalid ]; then
    KR_STATE=fail; KR_REASON="package.json is not valid JSON"; return 0
  fi
  if [ "$declared" = yes ] && [ ! -d "$root/node_modules" ]; then
    KR_STATE=fail; KR_REASON="dependencies not installed (run npm ci --ignore-scripts first)"; return 0
  fi
  if [ "$KNIP_TOOL_OK" != true ]; then
    KR_STATE=missing; KR_REASON="knip not found and npx unavailable"; return 0
  fi
  (cd -- "$root" && "${KBIN[@]}" --reporter json --no-progress) >"$jf" 2>"$ef" || rc=$?
  case "$rc" in
    0) KR_STATE=ok0 ;;
    1)
      if summary=$(hp summary "$jf" 2>/dev/null); then
        KR_STATE=ok1; KR_REASON="$summary; triage files first, see SKILL.md ($jd)"
      else
        KR_STATE=fail; KR_REASON="knip error (exit 1); report unreadable, see $ed"
      fi
      ;;
    *) KR_STATE=fail; KR_REASON="knip error (exit $rc); see $ed" ;;
  esac
}

knip_note_fail() { # <root> <reason>
  KF_COUNT=$((KF_COUNT + 1))
  if [ "$KF_COUNT" -eq 1 ]; then KF_ROOT=$1; KF_REASON=$2; fi
}

knip_fail_text() {
  local p="" more=""
  if [ "$KNIP_ROOTS" != . ]; then p="root $KF_ROOT: "; fi
  if [ "$KF_COUNT" -gt 1 ]; then more=" (+$((KF_COUNT - 1)) more root(s) failing)"; fi
  printf '%s%s%s' "$p" "$KF_REASON" "$more"
}

run_knip() {
  knip_load_roots
  case "$KNIP_RSTATUS" in
    ERR) emit knip FAIL ".verify.json is not usable ($KNIP_RNOTE)"; return 0 ;;
    DISABLED) emit knip SKIPPED "disabled in .verify.json"; return 0 ;;
    NONE) emit knip SKIPPED "no package.json (no tracked package.json outside node_modules)"; return 0 ;;
  esac
  local have_base=false why root nn i=0 total=0
  if [ -e "$KNIP_BASELINE" ] || [ -L "$KNIP_BASELINE" ]; then
    if ! why=$(hp check-baseline "$KNIP_BASELINE" 2>/dev/null); then
      emit knip FAIL "baseline $KNIP_BASELINE is not usable (${why:-unreadable})"
      return 0
    fi
    have_base=true
  fi
  knip_find_tool
  if [ "$KNIP_ROOTS" != . ]; then
    : >"$OUT/knip-roots.txt"
    while IFS= read -r root; do
      [ -n "$root" ] || continue
      i=$((i + 1))
      printf '%02d %s\n' "$i" "$root" >>"$OUT/knip-roots.txt"
    done <<<"$KNIP_ROOTS"
  fi
  KF_COUNT=0; KF_ROOT=""; KF_REASON=""; KPAIRS=()
  i=0
  while IFS= read -r root; do
    [ -n "$root" ] || continue
    i=$((i + 1)); total=$i
    nn=$(printf '%02d' "$i")
    knip_root_run "$root" "$nn"
    case "$KR_STATE" in
      missing) emit knip MISSING-TOOL "$KR_REASON"; return 0 ;;
      ok0) ;;
      ok1)
        if [ "$have_base" = true ]; then
          KPAIRS+=("$root" "$KR_JSON")
        else
          knip_note_fail "$root" "$KR_REASON"
        fi
        ;;
      *) knip_note_fail "$root" "$KR_REASON" ;;
    esac
  done <<<"$KNIP_ROOTS"
  if [ "$KF_COUNT" -gt 0 ]; then
    emit knip FAIL "$(knip_fail_text)"
    return 0
  fi
  if [ "$have_base" != true ]; then
    if [ "$KNIP_ROOTS" = . ]; then
      emit knip PASS "0 findings"
    else
      emit knip PASS "0 findings in $total root(s)"
    fi
    return 0
  fi
  # Baseline gate: only keys that are absent from the committed baseline fail.
  local res nnew nbase nres first more=""
  if [ "${#KPAIRS[@]}" -gt 0 ]; then
    res=$(hp gate "$KNIP_BASELINE" "$OUT/knip-new.txt" "${KPAIRS[@]}" 2>/dev/null) || res=""
  else
    res=$(hp gate "$KNIP_BASELINE" "$OUT/knip-new.txt" 2>/dev/null) || res=""
  fi
  if [ -z "$res" ]; then
    emit knip FAIL "knip report unreadable while comparing with the baseline; see $OUT_DISP/knip.err"
    return 0
  fi
  nnew=$(printf '%s\n' "$res" | sed -n 1p)
  nbase=$(printf '%s\n' "$res" | sed -n 2p)
  nres=$(printf '%s\n' "$res" | sed -n 3p)
  first=$(printf '%s\n' "$res" | sed -n 4p)
  if [ "$nnew" -eq 0 ]; then
    emit knip PASS "0 new findings ($nbase baseline, $nres resolved since baseline)"
  else
    if [ "$nnew" -gt 1 ]; then more=" (+$((nnew - 1)) more)"; fi
    emit knip FAIL "$nnew new finding(s) not in baseline: $first$more; see $OUT_DISP/knip-new.txt"
  fi
}

# ----------------------------------------------------------------------- jscpd
# Only the default exact-clone pass gates. Renamed or similar-structure passes are
# never run here: they are noisy leads to read by hand.
run_jscpd() {
  local jbin=()
  if command -v jscpd >/dev/null 2>&1; then
    jbin=(jscpd)
  elif command -v npx >/dev/null 2>&1; then
    jbin=(npx --yes jscpd@5.4.2)
  else
    emit jscpd MISSING-TOOL "jscpd not found and npx unavailable"
    return 0
  fi
  local args=()
  if [ -f .jscpd.json ]; then
    args+=(--config .jscpd.json)
  else
    args+=(. --min-tokens 70 --ignore '**/.verify-out/**,**/node_modules/**,**/.git/**')
  fi
  local rc=0 rep="$OUT/jscpd/jscpd-report.json"
  mkdir -p "$OUT/jscpd"
  if [ "$MODE" = range ]; then
    "${jbin[@]}" "${args[@]}" --baseline-from-ref "$BASE_SHA" --fail-on-new-clones 0 \
      --reporters ai,json --no-tips --output "$OUT/jscpd" >"$OUT/jscpd.ai.raw" 2>"$OUT/jscpd.err" || rc=$?
  else
    "${jbin[@]}" "${args[@]}" --reporters json --no-tips --output "$OUT/jscpd" \
      >"$OUT/jscpd.ai.raw" 2>"$OUT/jscpd.err" || rc=$?
  fi
  sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' "$OUT/jscpd.ai.raw" >"$OUT/jscpd.ai.txt" || true
  rm -f "$OUT/jscpd.ai.raw"

  # sources, clones, newClones, first new clone (one value per line)
  local parsed="" sources="" clones="" newc="" first="" pct="" parse_ok=false
  if [ -f "$rep" ] && parsed=$(python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
s = d.get("statistics", {}) or {}
t = s.get("total", s) or {}
dups = d.get("duplicates", []) or []
new = [x for x in dups if x.get("isNew")]
def f(x):
    a, b = x["firstFile"], x["secondFile"]
    return "%s:%s-%s ~ %s:%s-%s" % (a["name"], a["start"], a["end"], b["name"], b["start"], b["end"])
print(t.get("sources", 0))
print(t.get("clones", 0))
print(t.get("newClones", len(new)))
print(f(new[0]) if new else "")
print("%.1f" % float(t.get("percentage", 0)))
' "$rep" 2>/dev/null); then
    parse_ok=true
    sources=$(printf '%s\n' "$parsed" | sed -n 1p)
    clones=$(printf '%s\n' "$parsed" | sed -n 2p)
    newc=$(printf '%s\n' "$parsed" | sed -n 3p)
    first=$(printf '%s\n' "$parsed" | sed -n 4p)
    pct=$(printf '%s\n' "$parsed" | sed -n 5p)
  fi

  if [ "$rc" -eq 0 ]; then
    if [ "$parse_ok" != true ]; then
      # Fail closed: a run whose report cannot be read proves nothing.
      emit jscpd FAIL "jscpd exited 0 but its JSON report is missing or unreadable; see $OUT_DISP/jscpd.err"
    elif [ "${sources:-0}" -eq 0 ]; then
      emit jscpd SKIPPED "no source files in jscpd scope"
    elif [ "$MODE" = range ]; then
      emit jscpd PASS "0 new clones (head $clones clones, $clones in baseline ignored)"
    else
      emit jscpd SKIPPED "no base to diff against (baseline: $clones clones, $pct% duplicated lines in $sources files); use --range for the introduced-clones gate"
    fi
  elif [ "$rc" -eq 1 ] && [ "$MODE" = range ] && [ "$parse_ok" = true ] && [ "${newc:-0}" -gt 0 ]; then
    local more=""
    if [ "$newc" -gt 1 ]; then more=" (+$((newc - 1)) more)"; fi
    emit jscpd FAIL "$newc new clone(s): $first$more; see $OUT_DISP/jscpd.ai.txt"
  else
    emit jscpd FAIL "jscpd error (exit $rc); see $OUT_DISP/jscpd.err"
  fi
}

# ------------------------------------------------------------------ osv-scanner
run_osv() {
  if ! command -v osv-scanner >/dev/null 2>&1; then
    emit osv-scanner MISSING-TOOL "osv-scanner not installed; install the pinned release (see SKILL.md)"
    return 0
  fi
  local rc=0
  osv-scanner scan source -r --format json --output-file "$OUT/osv.json" . >"$OUT/osv.err" 2>&1 || rc=$?
  case "$rc" in
    0)
      local npk=""
      npk=$(sed -nE 's/.*found ([0-9]+) packages?.*/\1/p' "$OUT/osv.err" 2>/dev/null | tail -1 || true)
      if [ -n "$npk" ]; then
        emit osv-scanner PASS "packages found, 0 vulnerabilities ($npk package(s))"
      else
        emit osv-scanner PASS "packages found, 0 vulnerabilities"
      fi
      ;;
    1)
      local ids=""
      if ids=$(python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
rows, ids = [], []
for r in d.get("results", []) or []:
    for p in r.get("packages", []) or []:
        pkg = p.get("package", {}) or {}
        for v in p.get("vulnerabilities", []) or []:
            fixed = []
            for a in v.get("affected", []) or []:
                for rg in a.get("ranges", []) or []:
                    for e in rg.get("events", []) or []:
                        if "fixed" in e:
                            fixed.append(str(e["fixed"]))
            vid = str(v.get("id", "?"))
            if vid not in ids:
                ids.append(vid)
            rows.append("%s %s %s fixed:%s" % (pkg.get("name", "?"), pkg.get("version", "?"), vid, ",".join(sorted(set(fixed))) or "unknown"))
open(sys.argv[2], "w").write("\n".join(rows) + "\n")
if not ids:
    sys.exit(3)
extra = " (+%d more)" % (len(ids) - 5) if len(ids) > 5 else ""
print(", ".join(ids[:5]) + extra)
' "$OUT/osv.json" "$OUT/osv-findings.txt" 2>/dev/null); then
        emit osv-scanner FAIL "vulnerabilities found: $ids; see $OUT_DISP/osv-findings.txt"
      else
        emit osv-scanner FAIL "vulnerabilities found (report unreadable); see $OUT_DISP/osv.err"
      fi
      ;;
    128) emit osv-scanner SKIPPED "no package sources found (exit 128: no supported lockfile)" ;;
    *)   emit osv-scanner FAIL "osv-scanner error (exit $rc); see $OUT_DISP/osv.err" ;;
  esac
}

# -------------------------------------------------------------- write-baseline
# Records today's knip findings and osv-scanner advisories. All validation and both tool
# runs happen before the first file is written; every failure is exit 2.
run_write_baseline() {
  printf 'MODE write-baseline\n'
  command -v osv-scanner >/dev/null 2>&1 || die2 "osv-scanner not installed; install the pinned release (see SKILL.md)"
  local today expiry why root nn i=0 rc=0 pfx=""
  today=$(hp today 0); expiry=$(hp today 30)

  # ---- knip: run every root, build the next knip.json in $OUT
  local knip_ran=false knip_skip="" nkeys=0 nroots=0
  knip_load_roots
  case "$KNIP_RSTATUS" in
    ERR) die2 ".verify.json is not usable ($KNIP_RNOTE)" ;;
    DISABLED) knip_skip="disabled in .verify.json" ;;
    NONE) knip_skip="no package.json (no tracked package.json outside node_modules)" ;;
    *)
      knip_find_tool
      if [ "$KNIP_ROOTS" != . ]; then pfx=1; fi
      KPAIRS=()
      while IFS= read -r root; do
        [ -n "$root" ] || continue
        i=$((i + 1)); nroots=$i
        nn=$(printf '%02d' "$i")
        knip_root_run "$root" "$nn"
        case "$KR_STATE" in
          ok0) ;;
          ok1) KPAIRS+=("$root" "$KR_JSON") ;;
          *)
            if [ -n "$pfx" ]; then die2 "root $root: $KR_REASON"; fi
            die2 "$KR_REASON"
            ;;
        esac
      done <<<"$KNIP_ROOTS"
      if [ "${#KPAIRS[@]}" -gt 0 ]; then
        nkeys=$(hp knip-next "$OUT/knip-baseline-next.json" "$KNIP_BASELINE" "knip $KNIP_VERSION" "$today" "${KPAIRS[@]}") \
          || die2 "could not build the knip baseline"
      else
        nkeys=$(hp knip-next "$OUT/knip-baseline-next.json" "$KNIP_BASELINE" "knip $KNIP_VERSION" "$today") \
          || die2 "could not build the knip baseline"
      fi
      knip_ran=true
      ;;
  esac

  # ---- osv-scanner: scan with the marked block stripped, compute the next osv-scanner.toml
  local osv_ran=false osv_skip="" cfg=() action="NOCHANGE" nplaced=0 nskip=0 res
  if [ -f osv-scanner.toml ]; then
    if ! why=$(hp osv-prep osv-scanner.toml "$OUT/osv-baseline-scan.toml"); then
      die2 "osv-scanner.toml: $why"
    fi
    cfg=(--config "$OUT/osv-baseline-scan.toml")
  fi
  : >"$OUT/osv-baseline-ids.txt"
  if [ "${#cfg[@]}" -gt 0 ]; then
    osv-scanner scan source -r "${cfg[@]}" --format json --output-file "$OUT/osv-baseline.json" . >"$OUT/osv-baseline.err" 2>&1 || rc=$?
  else
    osv-scanner scan source -r --format json --output-file "$OUT/osv-baseline.json" . >"$OUT/osv-baseline.err" 2>&1 || rc=$?
  fi
  case "$rc" in
    0) osv_ran=true ;;
    1)
      hp osv-collect "$OUT/osv-baseline.json" "$ROOT" "$OUT/osv-baseline-ids.txt" "$OUT/osv-baseline-paths.txt" >/dev/null \
        || die2 "osv-scanner reported vulnerabilities but its report is unreadable; see $OUT_DISP/osv-baseline.err"
      osv_ran=true
      ;;
    128) osv_skip="no package sources found (exit 128: no supported lockfile)" ;;
    *) die2 "osv-scanner error (exit $rc); see $OUT_DISP/osv-baseline.err" ;;
  esac
  if [ "$osv_ran" = true ]; then
    local existing=-
    if [ -f osv-scanner.toml ]; then existing=osv-scanner.toml; fi
    if ! res=$(hp osv-next "$existing" "$OUT/osv-baseline-next.toml" "$OUT/osv-baseline-ids.txt" "$today" "$expiry"); then
      die2 "osv-scanner.toml: $res"
    fi
    action=${res%% *}
    nplaced=$(printf '%s\n' "$res" | awk '{print $2}')
    nskip=$(printf '%s\n' "$res" | awk '{print $3}')
  fi

  # ---- write (nothing above wrote into the repository)
  if [ "$knip_ran" = true ]; then
    if [ -f "$KNIP_BASELINE" ] && cmp -s "$OUT/knip-baseline-next.json" "$KNIP_BASELINE"; then
      printf 'BASELINE knip UNCHANGED %s (%s key(s), %s root(s))\n' "$KNIP_BASELINE" "$nkeys" "$nroots"
    else
      mkdir -p "$(dirname "$KNIP_BASELINE")"
      cp "$OUT/knip-baseline-next.json" "$KNIP_BASELINE"
      printf 'BASELINE knip WROTE %s (%s key(s), %s root(s))\n' "$KNIP_BASELINE" "$nkeys" "$nroots"
    fi
  else
    printf 'BASELINE knip SKIPPED %s\n' "$knip_skip"
  fi
  if [ "$osv_ran" = true ]; then
    local note=""
    if [ "${nskip:-0}" -gt 0 ]; then note="; $nskip advisory(ies) already ignored outside the block"; fi
    case "$action" in
      NOCHANGE) printf 'BASELINE osv-scanner UNCHANGED osv-scanner.toml (%s entry(ies)%s)\n' "$nplaced" "$note" ;;
      DELETE)
        rm -f -- osv-scanner.toml
        printf 'BASELINE osv-scanner REMOVED osv-scanner.toml (no advisories left, file deleted)\n'
        ;;
      *)
        cp "$OUT/osv-baseline-next.toml" osv-scanner.toml
        if [ "${nplaced:-0}" -eq 0 ]; then
          printf 'BASELINE osv-scanner REMOVED verify-baseline block from osv-scanner.toml (no advisories left)\n'
        else
          printf 'BASELINE osv-scanner WROTE osv-scanner.toml (%s entry(ies), ignoreUntil %s%s)\n' "$nplaced" "$expiry" "$note"
        fi
        ;;
    esac
  else
    printf 'BASELINE osv-scanner SKIPPED %s\n' "$osv_skip"
  fi

  # ---- self-check: scan exactly as run_osv does; a baseline that does not take effect is an error
  if [ "$osv_ran" = true ]; then
    rc=0
    osv-scanner scan source -r --format json --output-file "$OUT/osv-verify.json" . >"$OUT/osv-verify.err" 2>&1 || rc=$?
    case "$rc" in
      0|128) ;;
      1)
        local n ids paths
        n=$(hp osv-collect "$OUT/osv-verify.json" "$ROOT" "$OUT/osv-verify-ids.txt" "$OUT/osv-verify-paths.txt" 2>/dev/null) || n="?"
        ids=$(head -3 "$OUT/osv-verify-ids.txt" 2>/dev/null | paste -sd, - | sed 's/,/, /g')
        paths=$(paste -sd, "$OUT/osv-verify-paths.txt" 2>/dev/null | sed 's/,/, /g')
        die2 "osv-scanner still reports $n advisory(ies) after the baseline was written (e.g. $ids). Likely causes: a block entry whose ignoreUntil has passed (fix the dependency, the date is never renewed), or a lockfile below the repository root (${paths:-none listed}) because a root osv-scanner.toml does not apply to subdirectories: put an osv-scanner.toml beside that lockfile. Files already written are kept; see $OUT_DISP/osv-verify.json"
        ;;
      *) die2 "osv-scanner self-check error (exit $rc); see $OUT_DISP/osv-verify.err" ;;
    esac
  fi
  exit 0
}

# ------------------------------------------------------------------------- main
main() {
  if [ "$MODE" = write-baseline ]; then
    run_write_baseline
  fi
  printf 'MODE %s\n' "$MODE_LABEL"
  run_gitleaks
  if [ "$MODE" = staged ]; then
    for c in knip jscpd osv-scanner; do
      emit "$c" SKIPPED "not part of --staged (fast pre-commit path); runs in --range/--full"
    done
  else
    run_knip
    run_jscpd
    run_osv
  fi
  if [ "$BLOCK" -eq 0 ]; then
    echo "VERDICT READY"
    exit 0
  fi
  echo "VERDICT NOT READY"
  exit 1
}

main
