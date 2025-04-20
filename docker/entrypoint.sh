#!/bin/sh
set -e

exec /app/vnts \
    -p "${VNT_PORT:-29872}" \
    -P "${VNT_WEB_PORT:-29870}" \
    -U "${VNT_USERNAME:-admin}" \
    -W "${VNT_PASSWORD:-admin}" \
    -l "${VNT_LOG_PATH:-/app/log/vnt.log}" \
    ${VNT_WHITE_TOKEN:+-w "$VNT_WHITE_TOKEN"} \
    ${VNT_GATEWAY:+-g "$VNT_GATEWAY"} \
    ${VNT_NETMASK:+-m "$VNT_NETMASK"} \
    ${VNT_FINGER:+--finger} \
    ${VNT_WG_SECRET_KEY:+--wg "$VNT_WG_SECRET_KEY"}