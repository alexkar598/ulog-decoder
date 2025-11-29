# nightly-bookworm-slim
FROM rustlang/rust@sha256:1c899f2b3c759fc607208c63e0b94fe0aabd618ca0dbbaec0158b1ddc32d2073 AS chef
# We only pay the installation cost once,
# it will be cached from the second build onwards
RUN apt update && apt install -y pkg-config libudev-dev
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release

FROM chef AS builder_win
RUN rustup target add x86_64-pc-windows-gnu
RUN apt update && apt install -y gcc-mingw-w64-x86-64
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --target x86_64-pc-windows-gnu --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release --target x86_64-pc-windows-gnu

FROM scratch AS output
WORKDIR /

COPY --from=builder /app/target/release/ulog-decoder /

COPY --from=builder_win /app/target/x86_64-pc-windows-gnu/release/ulog-decoder.exe /
