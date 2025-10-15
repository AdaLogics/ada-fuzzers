// Copyright 2025 Ada Logics Ltd.
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
#include "config.h"
#include <fuzzer/FuzzedDataProvider.h>

#include <cc/data.h>
#include <cc/command_interpreter.h>

#include <dhcp6/parser_context.h>
#include <dhcp6/json_config_parser.h>
#include <dhcp6/ctrl_dhcp6_srv.h>
#include <process/daemon.h>
#include <log/logger_support.h>

#include "helper_func.h"

#include <array>
#include <vector>
#include <string>
#include <cstdlib>
#include <unistd.h>

using namespace isc::config;
using namespace isc::data;
using namespace isc::dhcp;

using ControlledDhcpvSrv = ControlledDhcpv6Srv;
static constexpr Parser6Context::ParserType parserTypes[] = {
    Parser6Context::PARSER_JSON, Parser6Context::PARSER_INTERFACES,
    Parser6Context::PARSER_OPTION_DATA, Parser6Context::PARSER_OPTION_DEF,
    Parser6Context::PARSER_OPTION_DEFS, Parser6Context::PARSER_HOST_RESERVATION,
    Parser6Context::PARSER_HOOKS_LIBRARY, Parser6Context::PARSER_DHCP_DDNS,
    Parser6Context::PARSER_CONFIG_CONTROL, Parser6Context::PARSER_HOST_RESERVATION,
    Parser6Context::PARSER_DHCP6, Parser6Context::SUBPARSER_DHCP6,
    Parser6Context::PARSER_SUBNET6, Parser6Context::PARSER_POOL6,
};

static const char* cmds[] = {
    "config-get","config-hash-get","config-write","config-set","config-test",
    "config-reload","dhcp-disable","dhcp-enable","version-get","build-report",
    "leases-reclaim","server-tag-get","config-backend-pull","status-get",
    "statistic-set-max-sample-count-all","statistic-set-max-sample-age-all",
    "subnet6-select-test","subnet6o6-select-test","lfc-start","shutdown"
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Initialise logging
    setenv("KEA_LOGGER_DESTINATION", "/dev/null", 0);
    setenv("KEA_LOCKFILE_DIR", "/tmp", 0);
    setenv("KEA_PIDFILE_DIR", "/tmp", 0);
    setenv("KEA_LFC_EXECUTABLE", "/bin/true", 0);
    try {
        isc::log::initLogger("fuzzer");
        isc::process::Daemon::loggerInit("fuzzer", false);
        isc::process::Daemon::setDefaultLoggerName("fuzzer");
    } catch (const isc::Exception&) {
        // Early exit if logging initialisation failed
        return 0;
    }

    // Set variables
    FuzzedDataProvider fdp(data, size);
    Parser6Context ctx;
    ControlledDhcpv6Srv srv(0, 0);

    // Get random flags
    const bool checkOnly = fdp.ConsumeBool();
    const bool extraChecks = fdp.ConsumeBool();

    // Get random type and command
    Parser6Context::ParserType type = parserTypes[fdp.ConsumeIntegralInRange<int>(0, 13)];
    std::string cmdStr = std::string(cmds[fdp.ConsumeIntegralInRange<int>(0, 19)]);

    // If no more remaining bytes, early exit
    if (fdp.remaining_bytes() <= 0) {
      return 0;
    }

    // Perform an evaluation of the raw data.
    std::string raw_payload(reinterpret_cast<const char*>(data), size);
    try {
        // General parsing
        ElementPtr rawTree = ctx.parseString(raw_payload, Parser6Context::PARSER_JSON);

        // Configure the server with valid tree
        if (rawTree) {
                configureDhcp6Server(srv, rawTree, false, true);
                ControlledDhcpv6Srv::checkConfig(rawTree);
                ControlledDhcpv6Srv::processConfig(rawTree);
        }
    } catch(const isc::Exception&){}

    // Generate random string
    const std::string payload = fdp.ConsumeRemainingBytesAsString();
    try {
        // General parsing
        ElementPtr tree = ctx.parseString(payload, type);

        // Configure the server with valid tree
        if (tree) {
            if (type == Parser6Context::PARSER_JSON || type == Parser6Context::PARSER_DHCP6){
                configureDhcp6Server(srv, tree, checkOnly, extraChecks);
                ControlledDhcpv6Srv::checkConfig(tree);
                ControlledDhcpv6Srv::processConfig(tree);
            }
        }
    } catch(const isc::Exception&){}

    try {
        // File base parsing
        std::string path = fuzz::writeTempFile(payload, "json");
        if (!path.empty()) {
            ElementPtr fileTree = ctx.parseFile(path, Parser6Context::PARSER_DHCP6);
            if (fileTree) {
                configureDhcp6Server(srv, fileTree, checkOnly, extraChecks);
                ControlledDhcpv6Srv::checkConfig(fileTree);
                ControlledDhcpv6Srv::processConfig(fileTree);
            }
            unlink(path.c_str());
        }
    }
    catch (const isc::Exception&){}

    try{
        // Command parsing
        ElementPtr args = fuzz::parseJSON(payload);
        ElementPtr cmd = Element::create(cmdStr);

        // Configure root element
        ElementPtr root = Element::createMap();
        root->set("command", cmd);
        root->set("arguments", args);

        // Transform to const element
        ConstElementPtr cmd_const = cmd;
        ConstElementPtr root_const = root;

        parseCommand(cmd_const, root_const);

        // Response answer parsing
        int status = 0;
        parseAnswer(status, fuzz::parseJSON(payload));
    } catch (const isc::Exception&) {
        // Known exceptions
    }
    return 0;
}

