#!/usr/bin/env bash
#
# This script builds the required plugins.
set -e

BINARY_SUFFIX=""
if [ "${GOOS}x" = "windowsx" ]; then
    BINARY_SUFFIX=".exe"
fi

# Get the parent directory of where this script is.
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
export DIR="$( cd -P "$( dirname "$SOURCE" )/.." && pwd )"

echo "==> Building plugins..."
rm -f $DIR/plugins/assets/plugin-*
for CURR_PLUGIN in $(ls $DIR/plugins/mains); do
    echo "working on: ${CURR_PLUGIN}"
    cd $DIR/plugins/mains/$CURR_PLUGIN;
    go build -v -o $DIR/plugins/assets/plugin-${CURR_PLUGIN}${BINARY_SUFFIX} .;
    cd $DIR;
done;
cd $DIR/plugins/assets;
for CURR_PLUGIN in $(ls plugin*); do
    gzip -f -9 $CURR_PLUGIN;
done;
cd $DIR;
