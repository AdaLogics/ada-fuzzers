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

/* libFuzzer harness for wolfBoot's ELF loader/parser (src/elf.c).
 *
 * Targets elf_load_image_mmu(), elf_open() and elf_hdr_pht_combined_size().
 * These functions parse untrusted ELF headers/program headers during
 * firmware loading -- a malformed firmware image fed to the bootloader is
 * exactly the threat model. Built with -DELF_PARSER so the loader walks
 * headers without writing to the (attacker-controlled) virtual addresses.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "elf.h"

int elf_load_image_mmu(uint8_t *image, uint32_t image_sz, uintptr_t *pentry,
    elf_mmu_map_cb mmu_cb);
int elf_open(const unsigned char *ehdr, int *is_elf32);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(elf32_header) || size > (1u << 20)) {
        return 0;
    }

    /* Writable copy: elf_load_image_mmu takes a non-const pointer. */
    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) return 0;
    memcpy(buf, data, size);

    uintptr_t entry = 0;
    elf_load_image_mmu(buf, (uint32_t)size, &entry, NULL);

    int is_elf32 = 0;
    if (size >= sizeof(elf64_header)) {
        elf_open(buf, &is_elf32);
    }

    free(buf);
    return 0;
}
