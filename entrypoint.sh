#!/bin/sh
set -e

export PGPASSWORD=$POSTGRES_PASSWORD

TABLE_COUNT=$(psql -h postgresql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -c \
  "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';" | xargs)

TABLE_COUNT=${TABLE_COUNT:-1}

if [ "$TABLE_COUNT" -eq 0 ]; then
  echo "Database empty, running prisma db push..."
  npx prisma db push
fi

exec npm run start -- -p $PORT