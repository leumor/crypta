#!/bin/sh
set -eu
: "${CRYPTAD_APP_TOKEN:?AppHost launch required}"
: "${CRYPTAD_MAIL_API_ENDPOINT:?Host-selected Platform API endpoint required}"
script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
exec java -cp "$script_dir/../lib/*" network.crypta.apps.mail.MailWorker
