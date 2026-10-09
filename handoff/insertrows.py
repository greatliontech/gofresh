#!/usr/bin/env python3
# Insert the new surface keys' digests into closure/toolchainaudit.go's
# rows by chain inheritance: a row gains a key exactly when the digest
# measured under that row's toolchain and selection differs from the
# value its Base chain already carries. Input: the canary's printed row
# literals (the worktree runs, one file per toolchain). Run from the
# gofresh root; gofmt realigns the map afterwards.
import re, sys, os
S = os.path.dirname(os.path.abspath(__file__))
TABLE = "closure/toolchainaudit.go"
NEW = ["go/ast", "go/build/constraint", "go/parser", "go/scanner", "go/token",
       "internal/fuzz", "os/exec", "os/signal", "runtime/pprof",
       "testing/internal/testdeps", "text/tabwriter"]

def printed_rows(path):
    """label -> {key: digest} for every row literal the canary printed."""
    rows, label, cur = {}, None, None
    for line in open(path):
        m = re.match(r'\s*Label:\s+"([^"]+)",', line)
        if m:
            label = m.group(1); cur = rows.setdefault(label, {}); continue
        m = re.match(r'\s*"([^"]+)":\s+"([0-9a-f]{64})",', line)
        if m and cur is not None:
            cur[m.group(1)] = m.group(2)
    return rows

def table_rows(src):
    """ordered list of (label, base, {key: digest}, span) from the table."""
    out = []
    for m in re.finditer(r'\t\{\n\t\tLabel:\s+"([^"]+)",\n(?:\t\tBase:\s+"([^"]+)",\n)?\t\tPackages: map\[string\]string\{\n(.*?)\n\t\t\},\n\t\},\n', src, re.S):
        label, base, body = m.group(1), m.group(2) or "", m.group(3)
        pk = dict(re.findall(r'"([^"]+)":\s+"([0-9a-f]{64})",', body))
        out.append((label, base, pk, m.span()))
    return out

def chain_value(rows_by_label, label, key):
    seen = set()
    while label and label not in seen:
        seen.add(label)
        row = rows_by_label.get(label)
        if row is None:
            return None
        if key in row["packages"]:
            return row["packages"][key]
        label = row["base"]
    return None

def main():
    src = open(TABLE).read()
    trows = table_rows(src)
    by_label = {l: {"base": b, "packages": dict(p)} for l, b, p, _ in trows}
    measured = {}
    for f in ["rows-dst13.txt", "rows-go1271.txt", "rows-go1270.txt"]:
        measured.update(printed_rows(os.path.join(S, "m315", f)))
    # every printed label must be a table row
    for label in measured:
        assert label in by_label, ("printed row is not a table row", label)
    # insertion in table order so a base's additions precede its deltas
    added = {}
    for label, base, pk, _ in trows:
        if label not in measured:
            continue
        digests = measured[label]
        for key in NEW:
            d = digests.get(key)
            if d is None:
                continue  # the selection does not build the key (e.g. a platform row's compiled-out file)
            # the value the chain carries without this row's own entry
            inherited = chain_value(by_label, base, key) if base else None
            if d != inherited:
                by_label[label]["packages"][key] = d
                added.setdefault(label, []).append(key)
    # rewrite the table bodies
    out, pos = [], 0
    for label, base, pk, (a, b) in trows:
        out.append(src[pos:a])
        block = src[a:b]
        pk2 = by_label[label]["packages"]
        body = "\n".join('\t\t\t%s: %s,' % ('"%s"' % k, '"%s"' % v) for k, v in sorted(pk2.items()))
        block = re.sub(r'(\t\tPackages: map\[string\]string\{\n).*?(\n\t\t\},)', lambda m: m.group(1) + body + m.group(2), block, count=1, flags=re.S)
        out.append(block); pos = b
    out.append(src[pos:])
    open(TABLE, "w").write("".join(out))
    for label in [l for l, _, _, _ in trows]:
        if label in added:
            print("%-32s +%d: %s" % (label, len(added[label]), ", ".join(added[label])))
    print("rows measured:", sorted(measured))

if __name__ == "__main__":
    main()
