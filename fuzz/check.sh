#!/bin/sh
# Consistency checks that need no fuzzing toolchain:
#   1. targets.txt, fuzz_targets/*.rs and the Cargo.toml [[bin]] names agree;
#   2. every package shared with the root Cargo.lock resolves to a version the
#      root also uses, so fuzzing exercises the dependencies that ship.
set -eu
cd "$(dirname "$0")"

listed=$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' targets.txt | cut -d' ' -f1 | sort)
sources=$(for file in fuzz_targets/*.rs; do basename "$file" .rs; done | sort)
bins=$(awk '/^\[\[bin\]\]/ { bin = 1; next } bin && /^name = / { gsub(/"/, "", $3); print $3; bin = 0 }' Cargo.toml | sort)

status=0
if [ "$listed" != "$sources" ] || [ "$listed" != "$bins" ]; then
    echo "fuzz targets disagree:" >&2
    echo "  targets.txt:    $(echo $listed)" >&2
    echo "  fuzz_targets/:  $(echo $sources)" >&2
    echo "  Cargo.toml:     $(echo $bins)" >&2
    status=1
fi

versions() {
    awk '/^name = / { gsub(/"/, "", $3); name = $3 } /^version = / { gsub(/"/, "", $3); print name, $3 }' "$1" | sort -u
}
versions ../Cargo.lock > target-root-versions.tmp
versions Cargo.lock > target-fuzz-versions.tmp
# A shared package may add a version of its own (a fuzz-only dependency can
# need another major); it has drifted when none of its versions is the root's.
drift=$(awk 'NR == FNR { root[$1] = root[$1] " " $2; seen[$1 " " $2] = 1; next }
    $1 in root { fuzz[$1] = fuzz[$1] " " $2; if (($1 " " $2) in seen) shared[$1] = 1 }
    END { for (name in fuzz) if (!(name in shared)) print "  " name ": fuzz" fuzz[name] ", root" root[name] }' \
    target-root-versions.tmp target-fuzz-versions.tmp)
rm -f target-root-versions.tmp target-fuzz-versions.tmp
if [ -n "$drift" ]; then
    echo "fuzz/Cargo.lock differs from the root Cargo.lock:" >&2
    echo "$drift" >&2
    echo "Resynchronize as described in docs/fuzzing.md." >&2
    status=1
fi
exit $status
