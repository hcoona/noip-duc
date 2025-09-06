ARG RUST_VERSION=1.86
ARG DEBIAN_VERSION=bookworm

FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS build

ARG APP_NAME=noip-duc
WORKDIR /build

# Build with mounted source & cargo caches (BuildKit required):
#   DOCKER_BUILDKIT=1 docker build -f docker/debian/Dockerfile .
# or:
#   docker buildx build -f docker/debian/Dockerfile --progress=plain .

ENV CARGO_TERM_COLOR=always \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
    CARGO_TARGET_DIR=/build/target

RUN --mount=type=bind,source=.,target=/src,readonly \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    set -eux; \
    cp -a /src /.tmp_src; mv /.tmp_src src; \
    cargo build --manifest-path src/Cargo.toml --release --locked; \
    install -Dm755 "${CARGO_TARGET_DIR}/release/${APP_NAME}" /out/${APP_NAME};

FROM debian:${DEBIAN_VERSION}-slim AS final

ARG APP_NAME=noip-duc

WORKDIR /app

RUN useradd -m -s /usr/sbin/nologin nonroot

COPY --from=build /out/${APP_NAME} /app/${APP_NAME}

USER nonroot

ENTRYPOINT ["/app/noip-duc"]
