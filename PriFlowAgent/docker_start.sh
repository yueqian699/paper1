#!/bin/bash
set -u

if ! docker info >/dev/null 2>&1; then
    setsid nohup dockerd \
        --host=unix:///var/run/docker.sock \
        --host=tcp://0.0.0.0:2375 \
        --registry-mirror=https://docker.m.daocloud.io \
        </dev/null >/var/log/dockerd-d.log 2>&1 &
fi

for _ in $(seq 1 30); do
    if docker info --format '{{.ServerVersion}}'; then
        exit 0
    fi
    sleep 1
done

exit 1
