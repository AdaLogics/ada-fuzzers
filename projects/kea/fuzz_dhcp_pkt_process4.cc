// Copyright (C) 2025 Ada Logcis Ltd.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
////////////////////////////////////////////////////////////////////////////////
#include <config.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <dhcp/pkt4.h>
#include <dhcp/libdhcp++.h>
#include <dhcp4/ctrl_dhcp4_srv.h>
#include <log/logger_support.h>
#include <util/filesystem.h>

#include <cstddef>
#include <cstdint>
#include <vector>
#include <list>
#include <memory>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <cstdio>

#include "helper_func.h"

using namespace isc::dhcp;
using namespace isc::util;

namespace isc {
    namespace dhcp {
        class MyDhcpv4Srv : public ControlledDhcpv4Srv {
            public:
                bool fuzz_accept(const Pkt4Ptr& pkt) {
                    return accept(pkt);
                }

                static void fuzz_sanityCheck(const Pkt4Ptr& query) {
                    ControlledDhcpv4Srv::sanityCheck(query);
                }

                void fuzz_classifyPacket(const Pkt4Ptr& pkt) {
                    classifyPacket(pkt);
                }

        };
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 236) {
        // package size requires at least 236 bytes
        return 0;
    }

    // Disable validatePath checking to allow writing configuration file to /tmp
    isc::util::file::PathChecker::enableEnforcement(false);

    // Initialise logging
    setenv("KEA_LOGGER_DESTINATION", "/dev/null", 0);
    setenv("KEA_LOCKFILE_DIR", "/tmp", 0);
    setenv("KEA_PIDFILE_DIR", "/tmp", 0);
    setenv("KEA_LFC_EXECUTABLE", "/bin/true", 0);
    try {
        isc::log::initLogger("fuzzer");
        isc::process::Daemon::loggerInit("fuzzer", false);
        isc::process::Daemon::setDefaultLoggerName("fuzzer");
    } catch (...) {
        // Early exit if logging initialisation failed
        return 0;
    }

    std::string path = fuzz::writeTempConfig(true);
    if (path.empty()) {
        // Early exit if configuration file creation failed
        fuzz::deleteTempFile(path);
        return 0;
    }

    Pkt4Ptr pkt;
    std::unique_ptr<MyDhcpv4Srv> srv;

    // Package parsing
    try {
        pkt = Pkt4Ptr(new Pkt4(data, size));
        pkt->unpack();
    } catch (...) {
        // Early exit if package parsing failed.
        return 0;
    }

    // Configure random value in packet
    FuzzedDataProvider fdp(data, size);
    uint8_t typeChoice = fdp.ConsumeIntegralInRange<uint8_t>(0, 8);
    pkt->setType(static_cast<DHCPMessageType>(typeChoice));

    // Server initialisation
    try {
        srv.reset(new MyDhcpv4Srv());
        srv->init(path);
    } catch (...) {
        // Early exit if server initialisation failed.
        return 0;
    }

    if (!srv) {
        // Early exit if server initialisation failed.
        return 0;
    }

    // Call classifyPacket for packet checking
    try {
        srv->fuzz_classifyPacket(pkt);
    } catch (const isc::Exception& e) {
        // Slient exceptions
    }

    // Call accept for packet checking
    try {
        srv->fuzz_accept(pkt);
    } catch (const isc::Exception& e) {
        // Slient exceptions
    }

    // Call sanityCheck for packet checking
    try {
        MyDhcpv4Srv::fuzz_sanityCheck(pkt);
    } catch (const isc::Exception& e) {
        // Slient exceptions
    }

    // Call process functions after the accept and check
    try {
        srv->processDhcp4Query(pkt, fdp.ConsumeBool());
    } catch (const isc::Exception& e) {
        // Slient exceptions
    }

    srv.reset();

    // Remove temp configuration file
    fuzz::deleteTempFile(path);
    return 0;
}
