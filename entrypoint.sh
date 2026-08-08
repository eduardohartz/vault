#!/bin/sh
set -e

# Migrations are applied by the separate `migrate` service, which compose runs
# to completion before this container starts. The app image deliberately does
# not carry the Prisma CLI.
#
# server.js comes from Next's standalone output.
exec node server.js
