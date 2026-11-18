#!/bin/sh
# Copy committed fixtures into each target's local (git-ignored) corpus.
# Fixtures are inert data: this never executes, opens or installs them.
set -eu
cd "$(dirname "$0")"
fixtures=../tests/fixtures

seed() {
    target=$1
    shift
    mkdir -p "corpus/$target"
    for extension in "$@"; do
        for file in "$fixtures"/*."$extension"; do
            [ -f "$file" ] && cp "$file" "corpus/$target/"
        done
    done
    echo "$target: $(find "corpus/$target" -type f | wc -l | tr -d ' ') inputs"
}

seed parse_cms der bin crl
seed parse_pe exe
seed parse_cab_navx cab navx
seed parse_msi msi msp
seed parse_appx msix appx msixbundle appxbundle
seed parse_text ps1 psm1 psd1 ps1xml vbs vbe js jse wsf rdp
seed verify_binary exe msi msp cab navx msix appx msixbundle appxbundle
seed verify_text ps1 psm1 psd1 ps1xml vbs vbe js jse wsf rdp
