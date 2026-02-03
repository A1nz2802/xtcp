FROM alpine:latest

RUN apk update && apk add --no-cache \
  build-base \
  gdb \
  iptables \
  iproute2 \
  tcpdump \
  bash \
  entr

WORKDIR /workspace
