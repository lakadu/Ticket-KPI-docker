#!/bin/sh
set -e

# Wajib: WEBHOOK_CRON_SECRET dari env_file
: "${WEBHOOK_CRON_SECRET:?WEBHOOK_CRON_SECRET wajib di-set di .env}"

BACKEND_URL="${INTERNAL_BACKEND_URL:-http://backend:8001}"

echo "[cron] backend=$BACKEND_URL"
echo "[cron] writing crontab…"

# Tulis crontab dengan secret yang sudah di-expand
cat > /etc/crontabs/root <<EOF
# SLA warning + auto-escalation, tiap 30 menit
*/30 * * * * curl -sS -X POST -H "Authorization: Bearer ${WEBHOOK_CRON_SECRET}" "${BACKEND_URL}/api/cron/sla-check" >> /var/log/cron.log 2>&1

# KPI monthly snapshot, tanggal 1 tiap bulan pukul 01:00 UTC
0 1 1 * * curl -sS -X POST -H "Authorization: Bearer ${WEBHOOK_CRON_SECRET}" "${BACKEND_URL}/api/cron/kpi-snapshot" >> /var/log/cron.log 2>&1

# Weekly digest, Senin pukul 08:00 UTC
0 8 * * 1 curl -sS -X POST -H "Authorization: Bearer ${WEBHOOK_CRON_SECRET}" "${BACKEND_URL}/api/cron/weekly-digest" >> /var/log/cron.log 2>&1
EOF

touch /var/log/cron.log

echo "[cron] starting crond…"
# tail log ke stdout supaya kelihatan di docker logs
tail -F /var/log/cron.log &
exec crond -f -L /dev/stdout
