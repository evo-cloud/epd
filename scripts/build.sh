#!/bin/bash

BASE="${BASH_SOURCE[0]%/*}/.."

set -e

function go_build() {
    local dir="$1"
    local os="${2:-linux}" arch="${3:-$dir}"
    local outdir="bin/$os-$dir" outfile="bin/out/spf-$os-$dir.tar.gz"
    echo "$os-$dir"
    (
        cd "$BASE"
        rm -fr "$outdir"
        mkdir -p "$outdir" "bin/out"
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -o "$outdir" ./cmd/...
        tar -C "$outdir" -czf "$outfile" --owner=0 --group=0 .
        cd bin/out
        sha256sum "spf-$os-$dir.tar.gz" >>spf-sha256sum.txt
    )
}

function prepare_for_docker() {
    cd "$BASE"
    rm -fr "bin/docker"
    local bindir arch stagedir
    for bindir in bin/linux-*; do
        arch="${bindir#bin/linux-}"
        case "$arch" in 
            armhf) arch="arm/v7" ;;
            arm) arch="arm/v6" ;;
        esac
        stagedir="bin/docker/build/linux/$arch"
        mkdir -p "$stagedir"
        for f in "$bindir"/*; do
            ln "$f" "$stagedir/${f#bin/linux-*/}"
        done
    done
}

rm -fr "$BASE/bin/out"

go_build amd64
GOARM=7 go_build armhf linux arm
GOARM=6 go_build arm
go_build arm64
go_build amd64 darwin

prepare_for_docker
