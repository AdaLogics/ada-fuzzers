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
#include <config.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <dns/name.h>
#include <dns/tsig.h>
#include <dns/rdata.h>

#include <gss_tsig_context.h>
#include <gss_tsig_key.h>
#include <tkey_exchange.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

using namespace isc;
using namespace isc::dns;
using namespace isc::gss_tsig;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Prepare basic key crypto information
    std::string key_name = fdp.ConsumeRandomLengthString(64);
    if (key_name.empty()) key_name = "fuzz-key";
    std::string tsig_rdata_txt = fdp.ConsumeRandomLengthString(1024);
    std::string owner_txt = fdp.ConsumeRandomLengthString(128);
    const uint16_t qid = fdp.ConsumeIntegral<uint16_t>();
    const bool do_chunked = fdp.ConsumeBool();

    // Target correct key sign and verify
    try {
        std::vector<uint8_t> payload = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 2048));
        GssTsigKey key(key_name, payload);
        GssTsigContext ctx(key);

        std::string wire = fdp.ConsumeRandomLengthString(2048);
        ctx.sign(qid, wire.data(), wire.size());

        Name owner_name(owner_txt.empty() ? "fuzz." : owner_txt.c_str());
        rdata::any::TSIG tsig_rdata(tsig_rdata_txt);
        TSIGRecord record(owner_name, tsig_rdata);

        ctx.verify(&record, wire.data(), wire.size());
    } catch (const isc::Exception&) {
        // Slient exceptions
    }

    // Target key exchange
    try {
        auto val = fdp.ConsumeIntegralInRange<int>(-5, 10);
        TKeyExchange::statusToText(static_cast<TKeyExchange::Status>(val));
    } catch (const isc::Exception&) {
        // Slient exceptions
    }

    return 0;
}
