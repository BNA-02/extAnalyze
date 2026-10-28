# Sandbox images for `extanalyze --dynamic`. Three targets, one per browser flavour:
#
#   chromium-mv3  current Chrome for Testing (Manifest V3 extensions)
#   chromium-mv2  Chrome for Testing 126, the last line where Manifest V2 extensions load without
#                 flags or policy (current Chromium no longer loads them)
#   firefox       current Firefox (Mozilla release tarball) driven through geckodriver
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

# ── Firefox + geckodriver (pinned by version and SHA-256) ─────────────────────────────────────
FROM libs AS firefox-build
RUN dnf -y install --setopt=install_weak_deps=False xz gtk3 dbus-glib libXt libXcursor libXinerama \
      mesa-libEGL libXcomposite libXdamage && dnf clean all
ARG FIREFOX_VERSION=159.0
ARG FIREFOX_SHA256=54536fcd120af484d4c56272a5a1cf4af57b9c713d1a3b1e775da192dd541fcd
ARG GECKODRIVER_VERSION=0.37.1
ARG GECKODRIVER_SHA256=e815130ea95983e162ae91843b48d3a3ce991735635fce83a647afde21e09f7e
RUN curl -fsSLo /tmp/ff.tar.xz \
      "https://archive.mozilla.org/pub/firefox/releases/${FIREFOX_VERSION}/linux-x86_64/en-US/firefox-${FIREFOX_VERSION}.tar.xz" \
    && echo "${FIREFOX_SHA256}  /tmp/ff.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/ff.tar.xz -C /opt \
    && curl -fsSLo /tmp/gd.tgz \
      "https://github.com/mozilla/geckodriver/releases/download/v${GECKODRIVER_VERSION}/geckodriver-v${GECKODRIVER_VERSION}-linux64.tar.gz" \
    && echo "${GECKODRIVER_SHA256}  /tmp/gd.tgz" | sha256sum -c - \
    && tar -xzf /tmp/gd.tgz -C /opt
RUN mkdir -p /opt/browserlibs \
    && for f in /opt/firefox/firefox /opt/firefox/*.so; do ldd "$f" 2>/dev/null; done \
       | awk '/=> \//{print $3}' | sort -u \
       | grep -Ev '^/opt/firefox/|/(libc|libm|libpthread|libdl|librt|libresolv|libutil)\.so' \
       | xargs -r -I{} cp -L {} /opt/browserlibs/ \
    && cp -L /usr/lib64/libsoftokn3.so /usr/lib64/libfreebl3.so /usr/lib64/libfreeblpriv3.so \
             /usr/lib64/libnssckbi.so /usr/lib64/libnssdbm3.so /opt/browserlibs/ 2>/dev/null || true \
    && cp -rL /usr/share/glib-2.0 /opt/glib-2.0 2>/dev/null || true
RUN (for f in /opt/firefox/firefox /opt/firefox/*.so; do ldd "$f" 2>&1 | grep "not found"; done) || true

# ── driver dependencies ───────────────────────────────────────────────────────────────────────
FROM ${BASE} AS driver
USER 0
WORKDIR /opt/sandbox
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY driver.mjs driver-firefox.mjs shared.mjs canary.mjs ./

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

FROM runtime-base AS firefox
COPY --from=firefox-build /opt/firefox /opt/firefox
COPY --from=firefox-build /opt/geckodriver /opt/geckodriver
COPY --from=firefox-build /opt/browserlibs /opt/browserlibs
ENV BROWSER_PATH=/opt/firefox/firefox GECKODRIVER=/opt/geckodriver MOZ_HEADLESS=1 MOZ_DISABLE_CONTENT_SANDBOX=1
ENTRYPOINT ["node", "/opt/sandbox/driver-firefox.mjs"]
