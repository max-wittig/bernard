FROM rust:1.30.0 AS base
WORKDIR /opt/bernard
COPY . .
RUN cargo build --release

FROM debian
WORKDIR /opt/bernard
COPY --from=base /opt/bernard/target/release/bernard /opt/bernard/bernard
RUN apt-get update && \
    apt-get install -y \
      nmap && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["./bernard"]
CMD ["-h"]
