#!/bin/sh

echo "[Generating configure file ...]"
echo "  |-> Run ./configure, and then make"
autoconf configure.ac > configure
chmod +x ./configure
