#!/bin/bash
set -e

source ${SCRIPTS_DIR}/lib/debug_functions
source ${SCRIPTS_DIR}/lib/find_functions

PACKAGES="$(find_go_pkg_dirs) *.go"

if [[ $(goimports -l ${PACKAGES} | wc -l) -gt 0 ]]; then
    echo "Incorrect formatting"
    echo "These are the files with formatting errors:"
    goimports -l ${PACKAGES}
    echo "These are the formatting errors:"
    goimports -d ${PACKAGES}
    exit 1
fi

golangci-lint run --timeout 5m $@

