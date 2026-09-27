FROM rust:1.85-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=build /src/target/release/packettrain-index /usr/local/bin/packettrain-index
ENTRYPOINT ["packettrain-index"]
