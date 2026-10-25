# Minimal, unprivileged sandbox image for REA dynamic analysis.
#
# Deliberately small. It carries a shell, coreutils and the two tracing
# utilities the runner needs, plus curl and netcat so a sample that tries to
# download a payload or open a reverse shell produces observable telemetry
# instead of failing on a missing binary. No package manager runs at runtime
# and there is no network unless the operator explicitly removes --network none.
FROM alpine:3.19

RUN apk add --no-cache \
        strace \
        bash \
        coreutils \
        file \
        curl \
        netcat-openbsd \
        socat \
 && adduser -D -u 1000 -s /bin/sh analyst \
 && mkdir -p /sample /work \
 && chown -R analyst:analyst /work

# Unprivileged by default; the runner also drops every capability.
USER analyst
WORKDIR /work
