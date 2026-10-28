# Sandbox images for `extanalyze --dynamic`. Three targets, one per browser flavour:
#
#   chromium-mv3  current Chrome for Testing (Manifest V3 extensions)
#   chromium-mv2  Chrome for Testing 126, the last line where Manifest V2 extensions load without
#                 flags or policy (current Chromium no longer loads them)
#   firefox       see Dockerfile.firefox
#
# Runtime base: Red Hat Hardened Images (Hummingbird), a minimal, non-root, no-package-manager
# image. Red Hat publishes no browser images, so Chrome is added from Google's pinned, checksummed
# Chrome-for-Testing builds, with its shared libraries assembled in a throwaway UBI9 stage.
# Observation driver: playwright-core (pure JS) on the hardened Node.js image.
#
# Build context: this directory (extanalyze dynamic build copies it to a temp dir).

ARG BASE=registry.access.redhat.com/hi/nodejs:latest
ARG BUILDER=registry.access.redhat.com/ubi9/ubi:latest

# ── shared libraries Chrome needs, plus fonts and a throwaway TLS cert ────────────────────────
FROM ${BUILDER} AS libs
RUN dnf -y install --setopt=install_weak_deps=False unzip openssl nss nspr atk at-spi2-atk \
      at-spi2-core cups-libs libdrm libxkbcommon libXcomposite libXdamage libXfixes libXrandr \
      mesa-libgbm alsa-lib pango cairo libX11 libxcb libXext libXrender libXi libXtst dbus-libs \
      fontconfig dejavu-sans-fonts glib2 libstdc++ libgcc \
    && dnf clean all
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=extanalyze-sandbox" \
      -keyout /tmp/key.pem -out /tmp/cert.pem && chmod 0644 /tmp/key.pem /tmp/cert.pem

# ── Chrome for Testing (pinned by version and SHA-256) ────────────────────────────────────────
FROM libs AS chrome-mv3
ARG CHROME_VERSION=156.0.8078.73
ARG CHROME_SHA256=c51c24f0126534aaf6d21d1f85b8e243934b3951989dbb59a1f8aab8e32b20c1
RUN curl -fsSLo /tmp/chrome.zip \
      "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chrome-linux64.zip" \
    && echo "${CHROME_SHA256}  /tmp/chrome.zip" | sha256sum -c - \
    && unzip -q /tmp/chrome.zip -d /opt
RUN mkdir -p /opt/browserlibs \
    && ldd /opt/chrome-linux64/chrome | awk '/=> \//{print $3}' \
       | grep -Ev '/(libc|libm|libpthread|libdl|librt|libresolv|libutil)\.so' \
       | xargs -r -I{} cp -L {} /opt/browserlibs/ \
    && cp -L /usr/lib64/libsoftokn3.so /usr/lib64/libfreebl3.so /usr/lib64/libfreeblpriv3.so \
             /usr/lib64/libnssckbi.so /usr/lib64/libnssdbm3.so /opt/browserlibs/ 2>/dev/null || true

FROM libs AS chrome-mv2
ARG CHROME_VERSION=126.0.6478.182
ARG CHROME_SHA256=b76e2376c7e2b619ae45361281806f21295e8abaf50c4bde7749fb67199f8b4b
RUN curl -fsSLo /tmp/chrome.zip \
      "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chrome-linux64.zip" \
    && echo "${CHROME_SHA256}  /tmp/chrome.zip" | sha256sum -c - \
    && unzip -q /tmp/chrome.zip -d /opt
RUN mkdir -p /opt/browserlibs \
    && ldd /opt/chrome-linux64/chrome | awk '/=> \//{print $3}' \
       | grep -Ev '/(libc|libm|libpthread|libdl|librt|libresolv|libutil)\.so' \
       | xargs -r -I{} cp -L {} /opt/browserlibs/ \
    && cp -L /usr/lib64/libsoftokn3.so /usr/lib64/libfreebl3.so /usr/lib64/libfreeblpriv3.so \
             /usr/lib64/libnssckbi.so /usr/lib64/libnssdbm3.so /opt/browserlibs/ 2>/dev/null || true

# ── driver dependencies ───────────────────────────────────────────────────────────────────────
FROM ${BASE} AS driver
USER 0
WORKDIR /opt/sandbox
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY driver.mjs canary.mjs ./

# ── final images ──────────────────────────────────────────────────────────────────────────────
FROM ${BASE} AS runtime-base
ENV HOME=/tmp NODE_ENV=production BROWSER_LIBS=/opt/browserlibs FONTCONFIG_PATH=/etc/fonts
COPY --from=libs /usr/share/fonts /usr/share/fonts
COPY --from=libs /etc/fonts /etc/fonts
COPY --from=libs /tmp/cert.pem /tmp/key.pem /opt/sandbox/
COPY --from=driver /opt/sandbox /opt/sandbox
USER 65532
ENTRYPOINT ["node", "/opt/sandbox/driver.mjs"]

FROM runtime-base AS chromium-mv3
COPY --from=chrome-mv3 /opt/chrome-linux64 /opt/chrome-linux64
COPY --from=chrome-mv3 /opt/browserlibs /opt/browserlibs
ENV BROWSER_PATH=/opt/chrome-linux64/chrome

FROM runtime-base AS chromium-mv2
COPY --from=chrome-mv2 /opt/chrome-linux64 /opt/chrome-linux64
COPY --from=chrome-mv2 /opt/browserlibs /opt/browserlibs
ENV BROWSER_PATH=/opt/chrome-linux64/chrome MV2=1
