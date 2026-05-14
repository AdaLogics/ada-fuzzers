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
 * and fdt_get_name(). This harness drives the header check first, then
 * walks the tree top-to-bottom over every reachable node and property to
 * exercise the bounds-checks at each level.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "fdt.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || size > (1u << 18)) return 0;

    /* fdt walkers take a non-const pointer for the mutation helpers, but
     * we only call read-only walkers here. Still, make a copy so any
     * accidental write would corrupt our memory rather than the input. */
    void *fdt = malloc(size);
    if (!fdt) return 0;
    memcpy(fdt, data, size);

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
