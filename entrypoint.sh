#!/bin/sh
set -e

TABLE_COUNT=$(PGPASSWORD=$POSTGRES_PASSWORD psql -h postgresql -U $POSTGRES_USER -d $POSTGRES_DB -t -c \
  "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';" | xargs)

if [ "$TABLE_COUNT" -eq 0 ]; then
  npx prisma db push
fi

exec npm run start -- -p $PORT