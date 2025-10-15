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

#include <agent/parser_context.h>
#include <agent/simple_parser.h>
#include <agent/ca_cfg_mgr.h>

#include <cc/data.h>
#include <exceptions/exceptions.h>

#include <string>
#include <memory>

using namespace isc::agent;
using namespace isc::data;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    bool checkOnly = fdp.ConsumeBool();

    AgentSimpleParser simpleParser;
    CtrlAgentCfgContextPtr ctxPtr(new CtrlAgentCfgContext());
    ParserContext ctx;
    ElementPtr elem;

    // Generate random parsing mode
    const uint8_t mode = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
    ParserContext::ParserType type = ParserContext::PARSER_JSON;
    if (mode == 1) {
        type = ParserContext::PARSER_AGENT;
    } else if (mode == 2) {
        type = ParserContext::PARSER_SUB_AGENT;
    }

    const std::string payload = fdp.ConsumeRemainingBytesAsString();

    // Target context parseString
    try {
        ctx.parseString(payload, type);
    } catch (const isc::Exception&) {
        // Slient exceptions
    }

    // Parse payload to JSON
    try {
        elem = Element::fromJSON(payload);
    } catch (...) {
        // If failed to parse the payload, early exit
        return 0;
    }

    // Target SimpleParser
    try {
        AgentSimpleParser::setAllDefaults(elem);
        simpleParser.checkTlsSetup(elem);
        simpleParser.parse(ctxPtr, elem, checkOnly);
    } catch (const isc::Exception&) {
        // Slient exceptions
    }

    return 0;
}
