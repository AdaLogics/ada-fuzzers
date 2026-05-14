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

/* libFuzzer harness for wolfBoot's clean-room gzip/DEFLATE inflater
 * (src/gzip.c, wolfBoot_gunzip). FIT images can wrap firmware payloads
 * in gzip; the bootloader inflates them before signature verification, so
 * the inflater operates on attacker-controlled bytes.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "gzip.h"

#define OUT_MAX (1u << 20) /* 1 MiB output cap */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > (1u << 18)) return 0;

    uint8_t *out = (uint8_t *)malloc(OUT_MAX);
    if (!out) return 0;

    uint32_t out_len = 0;
    (void)wolfBoot_gunzip(data, (uint32_t)size, out, OUT_MAX, &out_len);

    free(out);
    return 0;
}
