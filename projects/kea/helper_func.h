// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
#pragma once

#include <string>
#include <cc/data.h>

static const std::string JSON_CONFIG4 = R"CONFIG(
    {
        "Dhcp4":{
            "interfaces-config": {
                "interfaces": [ "eth0" ]
            },
            "lease-database": {
                "type": "memfile",
                "lfc-interval": 3600
            },
            "valid-lifetime": 4000,
            "subnet4": [{
                "pools": [ { "pool":  "192.0.2.1 - 192.0.2.200" } ],
                "id": 1,
                "subnet": "192.0.2.0/24",
                "interface": "eth0"
            }],
            "loggers": [{
                "name": "kea-dhcp4",
                "output-options": [{
                    "output": "stdout"
                }],
                "severity": "INFO"
            }]
        }
    })CONFIG";

static const std::string JSON_CONFIG6 = R"CONFIG(
    {
        "Dhcp6": {
            "interfaces-config": {
                "interfaces": [ "eth0" ]
            },
            "option-data": [{
                "name": "dns-servers",
                "data": "2001:db8::1, 2001:db8::2"
            }],
            "lease-database": {
                "type": "memfile",
                "lfc-interval": 3600
            }
        }
    })CONFIG";

namespace fuzz {
    std::string writeTempConfig(bool isV4);
    std::string writeTempFile(const std::string& payload, const char* suffix = "json");
    void deleteTempFile(std::string file_path);
    isc::data::ElementPtr parseJSON(const std::string& s);
}
