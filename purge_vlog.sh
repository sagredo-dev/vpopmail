#!/bin/sh
#
# Purge the vpopmail.vlog table

set -e

MYSQLBIN=$(command -v mysql)
if [ -z "$MYSQLBIN" ]; then
  echo "mysql client not found" >&2
  exit 1
fi

# get the vpopmail dir
VPOPMAILDIR=$(getent passwd vpopmail | cut -d: -f6)
if [ ! -d $VPOPMAILDIR ]; then
  echo "${VPOPMAILDIR} dir not found"
  exit 1
fi

# Config path
VPOPMAIL_MYSQL_CONFIG="${VPOPMAILDIR}/etc/vpopmail.mysql"
if [ ! -r $VPOPMAIL_MYSQL_CONFIG ]; then
  echo "${VPOPMAIL_MYSQL_CONFIG} file not found"
  exit 1
fi

# Extract mysql params
HOST=$(sed -n "/#/! s/^\(.*\)|.*|.*|.*|.*/\1/p" $VPOPMAIL_MYSQL_CONFIG)
PORT=$(sed -n "/#/! s/^.*|\(.*\)|.*|.*|.*/\1/p" $VPOPMAIL_MYSQL_CONFIG)
 USR=$(sed -n "/#/! s/^.*|.*|\(.*\)|.*|.*/\1/p" $VPOPMAIL_MYSQL_CONFIG)
 PWD=$(sed -n "/#/! s/^.*|.*|.*|\(.*\)|.*/\1/p" $VPOPMAIL_MYSQL_CONFIG)
  DB=$(sed -n "/#/! s/^.*|.*|.*|.*|\(.*\)/\1/p" $VPOPMAIL_MYSQL_CONFIG)

# Run the query
$MYSQLBIN -u"$USR" -p"$PWD" -h "$HOST" -P "$PORT" "$DB" << __EOF__
DELETE FROM vpopmail.vlog
WHERE timestamp < UNIX_TIMESTAMP(DATE_FORMAT(NOW(), '%Y-%m-01'));
__EOF__

exec "$@"
