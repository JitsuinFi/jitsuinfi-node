# Runtime image only: CI builds jitsuin-node and zcash-devtool on ubuntu-24.04 and copies the two
# binaries here, so Railway never compiles (fast deploys). Same base as the CI runner, so the
# binaries find the same glibc and libraries.
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 libssl3t64 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 node
COPY bin/jitsuin-node bin/zcash-devtool /usr/local/bin/
ENV DATA_DIR=/data ZCASH_DEVTOOL=/usr/local/bin/zcash-devtool NETWORK=test
# The Railway Volume is mounted at /data; the node makes its keys and wallets there on first start.
CMD ["jitsuin-node", "serve"]
