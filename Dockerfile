# syntax=docker/dockerfile:1.7
# Multi-architecture image (linux/amd64, linux/arm64). The Rust binary is cross-compiled on
# the build platform, and the final stage only copies files, so no emulation is needed.
# Base images use plain tags: the weekly release rebuild picks up their security fixes.

FROM --platform=$BUILDPLATFORM rust:1.99-slim-trixie AS build
ARG TARGETARCH
ARG BUILDARCH
ARG TINI_VERSION=v0.19.0
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
    AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu; cross="gcc-x86-64-linux-gnu libc6-dev-amd64-cross"; \
             tini_sha=c5b0666b4cb676901f90dfcb37106783c5fe2077b04590973b885950611b30ee ;; \
      arm64) target=aarch64-unknown-linux-gnu; cross="gcc-aarch64-linux-gnu libc6-dev-arm64-cross"; \
             tini_sha=eae1d3aa50c48fb23b8cbdf4e369d0910dfc538566bfd09df89a774aa84a48b9 ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    packages="ca-certificates curl"; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then packages="$packages $cross"; fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends $packages; \
    rm -rf /var/lib/apt/lists/*; \
    rustup target add "$target"; \
    echo "$target" > /rust-target; \
    curl -fsSL -o /tini "https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static-${TARGETARCH}"; \
    echo "$tini_sha  /tini" | sha256sum -c -; \
    chmod 0755 /tini; \
    mkdir -p /skel/data

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY web ./web
RUN --mount=type=cache,id=filefender-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=filefender-target-${TARGETARCH},target=/src/target \
    set -eux; \
    target="$(cat /rust-target)"; \
    cargo build --release --locked --target "$target"; \
    cp "target/$target/release/filefender" /filefender

# Official ClamAV image; its bundled signatures seed /data on the first start.
FROM clamav/clamav-debian:1.5
LABEL org.opencontainers.image.title="FileFender" \
      org.opencontainers.image.description="Self-hosted malware scanning API: ClamAV and YARA-X in one container" \
      org.opencontainers.image.source="https://github.com/drslid/FileFender" \
      org.opencontainers.image.licenses="MIT AND GPL-2.0-only"
COPY --from=build /tini /usr/local/bin/tini
COPY --from=build /filefender /usr/local/bin/filefender
# The clamav user (uid 1000) of the base image owns the data volume.
COPY --from=build --chown=1000:1000 /skel/data /data
# Uploads and archive extraction go to disk, not RAM.
ENV FILEFENDER_DATA_DIR=/data \
    FILEFENDER_TMP_DIR=/data/tmp
USER 1000:1000
VOLUME ["/data"]
EXPOSE 80 443 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10m --retries=3 \
    CMD ["/usr/local/bin/filefender", "healthcheck", "--ready"]
ENTRYPOINT ["/usr/local/bin/tini", "--", "/usr/local/bin/filefender"]
CMD ["serve"]
