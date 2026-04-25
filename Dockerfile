FROM rust:1.95.0-slim-trixie AS chef

WORKDIR /app
RUN cargo install --locked cargo-chef

FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --bin pocket-shield

FROM gcr.io/distroless/cc-debian13:nonroot

COPY --from=builder /app/target/release/pocket-shield /pocket-shield
COPY config.example.toml /config.toml

ENV POCKET_SHIELD_CONFIG=/config.toml
EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/pocket-shield"]
