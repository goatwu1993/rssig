#!/bin/sh
# Copy committed fixtures into each target's local (git-ignored) corpus.
# Fixtures are inert data: this never executes, opens or installs them.
set -eu
cd "$(dirname "$0")"
./check.sh
fixtures=../tests/fixtures

sed -e 's/#.*//' -e '/^[[:space:]]*$/d' targets.txt | while read -r target extensions; do
    mkdir -p "corpus/$target"
    for extension in $extensions; do
        for file in "$fixtures"/*."$extension"; do
            if [ -f "$file" ]; then cp "$file" "corpus/$target/"; fi
        done
    done
    echo "$target: $(find "corpus/$target" -type f | wc -l | tr -d ' ') inputs"
done
