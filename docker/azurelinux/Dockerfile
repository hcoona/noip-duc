ARG RUST_VERSION=1.75

# ============ Build Stage ============
FROM mcr.microsoft.com/azurelinux/base/rust:${RUST_VERSION} AS build

ARG APP_NAME=noip-duc
WORKDIR /build

# Build with BuildKit source & cache mounts examples:
#   docker buildx build -f docker/azurelinux/Dockerfile \
#     --progress=plain .
# Or simply:
#   DOCKER_BUILDKIT=1 docker build -f docker/azurelinux/Dockerfile .
# Lines using --mount require BuildKit.

# Notes:
# 1. Source is mounted read-only at /src so build artifacts never leak back.
# 2. Cache mounts keep registry/git/target between builds for speed.
# 3. Source is copied into /build/src before compiling to keep host clean.

ENV CARGO_TERM_COLOR=always \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
    CARGO_TARGET_DIR=/build/target

# (Optional) You could pre-copy only Cargo.toml/Cargo.lock for dependency caching.
# Here we copy everything for simplicity; cache mounts still give good reuse.
RUN --mount=type=bind,source=.,target=/src,readonly \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    set -eux; \
    cp -a /src /.tmp_src; mv /.tmp_src src; \
    cargo build --manifest-path src/Cargo.toml --release --locked; \
    install -Dm755 "${CARGO_TARGET_DIR}/release/${APP_NAME}" /out/${APP_NAME};

# ============ Final Stage ============
FROM mcr.microsoft.com/azurelinux/distroless/base:3.0 AS final
ARG APP_NAME=noip-duc
WORKDIR /app
COPY --from=build /out/${APP_NAME} /app/${APP_NAME}
USER 65532:65532
ENTRYPOINT ["/app/noip-duc"]
