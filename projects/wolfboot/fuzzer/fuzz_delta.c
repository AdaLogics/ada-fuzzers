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

/* libFuzzer harness for wolfBoot's delta-update patcher (src/delta.c).
 *
 * wb_patch_init() and wb_patch() consume a "patch" stream produced by
 * the host-side delta tool (or, in our threat model, by an attacker)
 * and reconstruct the new firmware image. The patch byte-stream is a
 * custom Bentley/McIlroy-style format with escape-byte framing and
 * variable-length src-offset/length headers -- a clear parser target.
 *
 * The harness splits the fuzzer input into a fake source image, a patch
 * stream, and reuses a fixed-size destination block fed back into
 * wb_patch() in a loop until the patch reports completion or error.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "delta.h"

#define SRC_SIZE  4096
#define DST_BLOCK 512

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || size > (1u << 17)) return 0;

    /* Split the input: first SRC_SIZE bytes (or all available) form the
     * source image; the remainder is the patch stream. */
    size_t src_sz = size > SRC_SIZE ? SRC_SIZE : size;
    size_t patch_sz = size - src_sz;
    if (patch_sz == 0) return 0;

    uint8_t *src = (uint8_t *)malloc(src_sz);
    uint8_t *patch = (uint8_t *)malloc(patch_sz);
    if (!src || !patch) { free(src); free(patch); return 0; }
    memcpy(src, data, src_sz);
    memcpy(patch, data + src_sz, patch_sz);

    WB_PATCH_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (wb_patch_init(&ctx, src, (uint32_t)src_sz,
                      patch, (uint32_t)patch_sz) == 0) {
        uint8_t dst[DST_BLOCK];
        int guard = 0;
        while (guard++ < 4096) {
            int r = wb_patch(&ctx, dst, sizeof(dst));
            if (r <= 0) break;
        }
    }

    free(src);
    free(patch);
    return 0;
}
