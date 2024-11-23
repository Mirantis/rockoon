#!/bin/sh

{{/*
Copyright 2019 The Openstack-Helm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/}}

set -ex

MYSQLCMD='mysql -r -N'
if [ $(echo 'show tables' | $MYSQLCMD | wc -c) -eq 0 ]; then
  echo "Create new DB schema"
  $MYSQLCMD < /etc/pdns/schema.sql
  exit 0
fi

if [ -f /etc/pdns/4.2.0_to_4.3.0_schema.mysql.sql ] && [ $(echo 'describe cryptokeys' | $MYSQLCMD | grep -c published) -eq 0 ]; then
  echo "Upgrade DB to 4.3.x schema"
  $MYSQLCMD < /etc/pdns/4.2.0_to_4.3.0_schema.mysql.sql
fi

if [ -f /etc/pdns/4.3.0_to_4.7.0_schema.mysql.sql ] && [ $(echo 'describe domains' | $MYSQLCMD | grep -c catalog) -eq 0 ]; then
  echo "Upgrade DB to 4.7.x schema"
  $MYSQLCMD < /etc/pdns/4.3.0_to_4.7.0_schema.mysql.sql
fi
