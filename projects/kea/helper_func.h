// Copyright (C) 2025 Ada Logcis Ltd.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
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
                "lfc-interval": 3600,
                "name": "/tmp/kea-leases4.csv"
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
                "lfc-interval": 3600,
                "name": "/tmp/kea-leases6.csv"
            }
        }
    })CONFIG";

namespace fuzz {
    std::string writeTempConfig(bool isV4);
    std::string writeTempFile(const std::string& payload, const char* suffix = "json");
    void deleteTempFile(std::string file_path);
    isc::data::ElementPtr parseJSON(const std::string& s);
}
