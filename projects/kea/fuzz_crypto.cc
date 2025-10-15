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

#include <dns/tsig.h>
#include <cryptolink/cryptolink.h>
#include <cryptolink/crypto_hmac.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <memory>

using namespace isc::dns;
using namespace isc::cryptolink;
using namespace isc::util;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::string secret = fdp.ConsumeRandomLengthString(64);
    std::string tsig_data = fdp.ConsumeRandomLengthString(1024);

    // TSIGContext
    try {
        // Create TSIGContext
        TSIGKey tsigkey("fuzz_key:" + secret);
        TSIGContext ctx(tsigkey);

        // TSIGContext sign
        uint16_t qid = fdp.ConsumeIntegral<uint16_t>();
        ctx.sign(qid, tsig_data.data(), tsig_data.size());

        // Create TSIGRecord
        Name name("fuzz_record");
        TSIGRecord record(name, rdata::any::TSIG(fdp.ConsumeRandomLengthString(1024)));

        ctx.verify(&record, tsig_data.data(), tsig_data.size());
    } catch (const isc::Exception&) {
        // Slient ezceptions
    }

    // HMAC
    try {
        // HMAC Sign
        OutputBuffer hmac(256);
        signHMAC(tsig_data.data(), tsig_data.size(), secret.data(), secret.size(),
            static_cast<HashAlgorithm>(fdp.ConsumeIntegralInRange<int>(0, 6)), hmac);

        // HMAC Verify
        std::string sig = fdp.ConsumeRandomLengthString(256);
        verifyHMAC(tsig_data.data(), tsig_data.size(), secret.data(), secret.size(),
            static_cast<HashAlgorithm>(fdp.ConsumeIntegralInRange<int>(0, 6)),
            sig.data(), sig.size());
    } catch (const isc::Exception&) {
        // Slient ezceptions
    }

    return 0;
}
