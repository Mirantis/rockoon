#!/usr/bin/env python

{{/*
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

import os

# Mask permissions to files 416 dirs 0750
os.umask(0o027)
PLUGINS_CONF = "/tmp/pod-shared/heat_plugins.conf"

def get_plugin_dirs(plugin):
    _plugin = plugin.split("/", 1)
    _plugin[0] = os.path.dirname(__import__(_plugin[0]).__file__)
    return "/".join(_plugin)


plugin_dirs = [get_plugin_dirs(plugin) for plugin in os.environ["PLUGINS"].split(",")]

with open(PLUGINS_CONF, "w") as conf:
    conf.write("[DEFAULT]\nplugin_dirs = %s\n" % ",".join(plugin_dirs))
