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

/* libFuzzer harness for wolfBoot's Flattened Device Tree parser
 * (src/fdt.c). On PPC/aarch64 boot wolfBoot consumes a DTB blob handed
 * to it by the previous stage and walks it via fdt_check_header(),
 * fdt_next_node(), fdt_first_property_offset(), fdt_get_property_by_offset(),
 * and fdt_get_name().
 *
 * API contract notes (mirroring libfdt):
 *   - fdt_check_header() takes no size; the caller MUST guarantee at least
 *     sizeof(struct fdt_header) bytes of readable memory before calling.
 *   - The walkers (fdt_next_node, fdt_first_property_offset, ...) trust
 *     fdt_totalsize() and the offsets it advertises. To keep their reads
 *     inside our allocation we (1) require size >= fdt_totalsize, and
 *     (2) hand them a buffer whose true allocation is fdt_totalsize so any
 *     legitimately-out-of-range access is a real wolfBoot bug rather than
 *     a harness-side over-read.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>  /* ntohl */

#include "fdt.h"

#define MAX_FDT_SIZE (1u << 18)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Contract: fdt_check_header requires a full header to even peek at. */
    if (size < sizeof(struct fdt_header) || size > MAX_FDT_SIZE) {
        return 0;
    }

    /* Read advertised totalsize. fdt is big-endian on the wire; ntohl
     * works on the little-endian host OSS-Fuzz runs on. If the blob lies
     * about its own length, refuse it: the libfdt-style walkers will read
     * past the end with no recourse otherwise -- that is API misuse, not
     * a bug. */
    uint32_t total;
    memcpy(&total, data + offsetof(struct fdt_header, totalsize), 4);
    total = ntohl(total);
    if (total < sizeof(struct fdt_header) || total > size) {
        return 0;
    }

    /* Allocate exactly fdt_totalsize bytes so any read past the advertised
     * end lands in ASan-poisoned memory and surfaces as a real bug. */
    void *fdt = malloc(total);
    if (!fdt) {
        return 0;
    }
    memcpy(fdt, data, total);

    if (fdt_check_header(fdt) != 0) {
        free(fdt);
        return 0;
    }

    int depth = 0;
    int off = 0;
    int guard = 0;
    while (off >= 0 && guard++ < 4096) {
        off = fdt_next_node(fdt, off, &depth);
        if (off < 0) break;

        int name_len = 0;
        (void)fdt_get_name(fdt, off, &name_len);

        int poff = fdt_first_property_offset(fdt, off);
        int pguard = 0;
        while (poff >= 0 && pguard++ < 1024) {
            int plen = 0;
            (void)fdt_get_property_by_offset(fdt, poff, &plen);
            poff = fdt_next_property_offset(fdt, poff);
        }
    }

    free(fdt);
    return 0;
}
