#!/usr/bin/env bash
# Build a self-contained .deb: a managed standalone Python plus a hash-locked venv under
# /opt/extanalyze, with a /usr/bin/extanalyze wrapper. No dependency on the distro Python.
#
# Usage: packaging/build-deb.sh [output-dir]      (needs: uv, dpkg-deb, network)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/dist-deb}"
PYTHON_SERIES="${PYTHON_SERIES:-3.12}"
PREFIX=/opt/extanalyze

VERSION="$(python3 -c 'import tomllib,sys; print(tomllib.load(open(sys.argv[1],"rb"))["project"]["version"])' "$ROOT/pyproject.toml")"
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

STAGE="$(mktemp -d)"
WHEELS="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$WHEELS"' EXIT
mkdir -p "$STAGE$PREFIX" "$OUT"

echo ">> standalone Python $PYTHON_SERIES"
uv python install "$PYTHON_SERIES" --install-dir "$STAGE$PREFIX/python"
PY="$(find "$STAGE$PREFIX/python" -maxdepth 3 -path '*/bin/python3' | head -n1)"

echo ">> venv from uv.lock (hash-verified)"
uv venv --python "$PY" "$STAGE$PREFIX/venv"
(cd "$ROOT" && uv export --frozen --no-emit-project --format requirements-txt -o "$WHEELS/requirements.txt")
uv pip install --python "$STAGE$PREFIX/venv/bin/python" --require-hashes --no-compile -r "$WHEELS/requirements.txt"

echo ">> project wheels"
(cd "$ROOT" && uv build --wheel -o "$WHEELS/wheels")
if [ -f "$ROOT/plugins/dynamic/pyproject.toml" ]; then
  (cd "$ROOT/plugins/dynamic" && uv build --wheel -o "$WHEELS/wheels")
fi
uv pip install --python "$STAGE$PREFIX/venv/bin/python" --no-deps --no-compile "$WHEELS"/wheels/*.whl

echo ">> make the tree relocatable to $PREFIX"
# Scripts, pyvenv.cfg and symlinks were created with the staging path baked in.
grep -rIl --exclude-dir=site-packages "$STAGE$PREFIX" "$STAGE$PREFIX" 2>/dev/null \
  | xargs -r sed -i "s|$STAGE$PREFIX|$PREFIX|g"
find "$STAGE$PREFIX" -type l | while read -r link; do
  target="$(readlink "$link")"
  case "$target" in
    "$STAGE$PREFIX"*) ln -sfn "$PREFIX${target#"$STAGE$PREFIX"}" "$link" ;;
  esac
done
sed -i "s|$STAGE$PREFIX|$PREFIX|g" "$STAGE$PREFIX"/venv/bin/extanalyze

echo ">> package metadata"
install -d "$STAGE/usr/bin" "$STAGE/usr/share/doc/extanalyze" "$STAGE/DEBIAN"
printf '#!/bin/sh\nexec %s/venv/bin/extanalyze "$@"\n' "$PREFIX" > "$STAGE/usr/bin/extanalyze"
chmod 0755 "$STAGE/usr/bin/extanalyze"
install -m 0644 "$ROOT/LICENSE" "$STAGE/usr/share/doc/extanalyze/copyright"

SIZE_KB="$(du -sk "$STAGE" | cut -f1)"
cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: extanalyze
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Installed-Size: $SIZE_KB
Depends: libc6 (>= 2.31)
Maintainer: Ahmed BN <ahmedbn.pro@outlook.com>
Homepage: https://github.com/BNA-02/extAnalyze
Description: Browser extension static analysis and threat intelligence CLI
 Downloads Chrome, Edge and Firefox extensions and analyzes them without executing
 them: manifest and permission scoring, code review, threat-intelligence lookups.
 Ships its own Python runtime under /opt/extanalyze.
CONTROL

DEB="$OUT/extanalyze_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB"
echo ">> built $DEB"
