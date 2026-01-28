#!/bin/sh
# generate_filc_map.sh - Prefix all exported symbols in libvarnishapi.map for Fil-C
if test x"$1" = x; then
  echo "Usage: $0 <directory containing libvarnishapi.map>" >&2
  exit 1
fi
DIR="$1"
SRC="$DIR/libvarnishapi.map"
DST="$DIR/libvarnishapi_filc.map"
if test ! -f "$SRC"; then
  echo "Error: $SRC not found" >&2
  exit 1
fi
sed -E 's/^([ \t]{2})(V[a-zA-Z0-9_]*);$/\1pizlonated_\2;/g' "$SRC" > "$DST"
chmod 644 "$DST"
prefixed=$(grep 'pizlonated_' "$DST" | wc -l)
echo "Generated $DST (prefixed $prefixed symbols)"
