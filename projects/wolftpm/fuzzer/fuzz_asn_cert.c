/* Copyright 2026 Ada Logics Ltd
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* libFuzzer harness for wolfTPM ASN.1 decoders.
 *
 * Targets TPM2_ASN_DecodeX509Cert and TPM2_ASN_DecodeRsaPubKey, which
 * parse untrusted bytes (EK certificates, RSA public keys returned from
 * a TPM) into wolfTPM data structures. These functions handle attacker-
 * influenced input (e.g. a malicious or malformed EK certificate read
 * from a TPM NV index) and are an obvious attack surface for parser
 * bugs (length confusions, out-of-bounds reads, integer overflows).
 *
 * The two entry points are split on the first input byte so the fuzzer
 * can drive both decoders from a single corpus.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <wolftpm/tpm2_asn.h>
#include <wolftpm/tpm2_wrap.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) {
        return 0;
    }

    uint8_t selector = data[0];
    const uint8_t *payload = data + 1;
    int payloadSz = (int)(size - 1);

    /* The decoders take a non-const pointer; duplicate the input. */
    uint8_t *buf = (uint8_t *)malloc((size_t)payloadSz);
    if (buf == NULL) {
        return 0;
    }
    memcpy(buf, payload, (size_t)payloadSz);

    if ((selector & 0x1) == 0) {
        DecodedX509 x509;
        memset(&x509, 0, sizeof(x509));
        (void)TPM2_ASN_DecodeX509Cert(buf, payloadSz, &x509);
    }
    else {
        TPM2B_PUBLIC pub;
        memset(&pub, 0, sizeof(pub));
        (void)TPM2_ASN_DecodeRsaPubKey(buf, payloadSz, &pub);
    }

    free(buf);
    return 0;
}
