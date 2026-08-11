# Build a static-ish release binary, then run it on a slim base.
FROM rust:1.97-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/nnt-auth /usr/local/bin/nnt-auth
ENV PORT=8080
EXPOSE 8080
CMD ["nnt-auth"]
