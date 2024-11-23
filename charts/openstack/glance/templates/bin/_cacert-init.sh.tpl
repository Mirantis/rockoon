#!/bin/bash

set -ex

{{ dict "envAll" . "objectType" "script_sh" "secretPrefix" "glance" | include "helm-toolkit.snippets.kubernetes_ssl_objects" }}
