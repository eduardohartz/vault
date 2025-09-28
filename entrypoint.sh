#!/bin/sh
set -e

npx prisma db push

exec npm run start -- -p $PORT