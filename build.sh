#!/usr/bin/env bash

set -eux pipefail

mkdir -p build

docker build . --output build