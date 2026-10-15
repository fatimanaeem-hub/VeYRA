#!/usr/bin/env bash
#
# Build the simulation toolchain used by the Veins job of the CI pipeline:
#   OMNeT++ 6.1 (command line only, no IDE, no Qt) and Veins 5.3.1.
#
# Everything goes into $TOOLS (default: ~/veyra-tools). The CI caches that
# folder, so this script only does real work on the first run of a branch.
#
#   bash ci/build_toolchain.sh
#
# Afterwards:  source "$TOOLS/omnetpp-6.1/setenv" -f
#              Veins is at "$TOOLS/veins-5.3.1"
#
set -euo pipefail

TOOLS="${TOOLS:-$HOME/veyra-tools}"
OMNETPP_URL="${OMNETPP_URL:-https://github.com/omnetpp/omnetpp/releases/download/omnetpp-6.1.0/omnetpp-6.1.0-linux-x86_64.tgz}"
VEINS_URL="${VEINS_URL:-https://github.com/sommer/veins/archive/refs/tags/veins-5.3.1.tar.gz}"
JOBS="$(nproc 2>/dev/null || echo 2)"

mkdir -p "$TOOLS"
cd "$TOOLS"

# ---------------------------------------------------------------- OMNeT++ 6.1
if [ ! -x omnetpp-6.1/bin/opp_run ] || [ ! -f omnetpp-6.1/lib/liboppsim.so ]; then
    echo "::group::Download OMNeT++ 6.1"
    rm -rf omnetpp-6.1
    if [ -n "${OMNETPP_TGZ:-}" ]; then tar xzf "$OMNETPP_TGZ"; else curl -fsSL "$OMNETPP_URL" | tar xz; fi
    echo "::endgroup::"

    echo "::group::Build OMNeT++ 6.1 (headless, release mode)"
    cd omnetpp-6.1
    # Command-line build only: no Qt GUI, no 3D view, no Python result bindings.
    sed -i -e 's/^WITH_QTENV=yes/WITH_QTENV=no/' \
           -e 's/^WITH_OSG=yes/WITH_OSG=no/' \
           -e 's/^WITH_OSGEARTH=yes/WITH_OSGEARTH=no/' \
           -e 's/^WITH_SCAVE_PYTHON_BINDINGS=yes/WITH_SCAVE_PYTHON_BINDINGS=no/' \
           -e 's/^USE_CCACHE_PREFIX=yes/USE_CCACHE_PREFIX=no/' configure.user
    # OMNeT++'s configure insists on the Python modules of its IDE analysis tool
    # (numpy<2, pandas<3, ...), so give it a private virtual environment.
    "${OPP_PYTHON:-python3}" -m venv "$TOOLS/opp-venv"
    "$TOOLS/opp-venv/bin/python" -m pip install -q --upgrade pip
    # (setuptools<81: the check imports pkg_resources, which newer setuptools dropped)
    "$TOOLS/opp-venv/bin/python" -m pip install -q -r python/requirements.txt "setuptools<81"
    PATH="$TOOLS/opp-venv/bin:$PATH"
    set +u; source setenv -f; set -u
    ./configure
    make -j"$JOBS" MODE=release base
    # Keep the cache small: object files and bundled docs/samples are not needed.
    rm -rf out doc samples ide images "$TOOLS/opp-venv"
    cd "$TOOLS"
    echo "::endgroup::"
else
    echo "OMNeT++ 6.1 already built in $TOOLS (cache hit)"
fi

set +u; source "$TOOLS/omnetpp-6.1/setenv" -f; set -u

# ---------------------------------------------------------------- Veins 5.3.1
if ! ls veins-5.3.1/src/libveins.so >/dev/null 2>&1; then
    echo "::group::Download and build Veins 5.3.1"
    rm -rf veins-5.3.1 veins-veins-5.3.1
    if [ -n "${VEINS_SRC:-}" ]; then
        cp -r "$VEINS_SRC" veins-5.3.1
    else
        curl -fsSL "$VEINS_URL" | tar xz
        mv veins-veins-5.3.1 veins-5.3.1
    fi
    cd veins-5.3.1
    ./configure
    make -j"$JOBS" MODE=release
    rm -rf out doc examples
    cd "$TOOLS"
    echo "::endgroup::"
else
    echo "Veins 5.3.1 already built in $TOOLS (cache hit)"
fi

echo "Toolchain ready:"
opp_run -v | head -2 || true
echo "  Veins $(env "$TOOLS/veins-5.3.1/print-veins-version" 2>/dev/null || echo '?') at $TOOLS/veins-5.3.1"
