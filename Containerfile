FROM scratch

ARG TARGETARCH

LABEL description="Exchange an X.509 cert for a JWT token deterministically"

USER 1001

COPY ./token-exchange-linux-$TARGETARCH /usr/bin/token-exchange

WORKDIR /

ENTRYPOINT ["/usr/bin/token-exchange"]
