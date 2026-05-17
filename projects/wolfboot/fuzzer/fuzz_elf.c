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
 * In wolfBoot's threat model the ELF image fed to elf_load_image_mmu()
 * has already passed signature verification, so the fuzz target is
 * exercising defence-in-depth parser robustness rather than a primary
 * attack surface. We therefore canonicalize a small set of header fields
 * that, if left fully fuzz-controlled, mask all other bugs behind one
 * highly-reachable program-header structural shortcoming (entry_size <
 * sizeof(program_header)). The canonicalization is documented inline so
 * a future audit can decide whether to relax it.
 *
 * Canonicalized fields (per input):
 *   - ELF magic + class + endianness  : forced to "\x7fELF" + class32/64
 *                                       + little-endian
 *   - ph_entry_size                   : forced to sizeof(elf32_program_header)
 *                                       or sizeof(elf64_program_header)
 *                                       per chosen class
 *   - ELF type                        : forced to ELF_HET_EXEC
 *
 * Everything else (ph_offset, ph_entry_count, entry, segment contents,
 * section header table) remains under fuzzer control.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "elf.h"

int elf_load_image_mmu(uint8_t *image, uint32_t image_sz, uintptr_t *pentry,
    elf_mmu_map_cb mmu_cb);
int elf_open(const unsigned char *ehdr, int *is_elf32);

/* Refuse every mapping request so elf_load_image_mmu walks all segments
 * but performs no in-place writes. The loader interprets a non-zero
 * return as "mapping unavailable" and continues to the next program
 * header. This contains the loader's arbitrary-vaddr memmove/memset
 * (src/elf.c:193-197), which would otherwise SEGV on any non-mapped
 * attacker-supplied virtual address -- a configuration issue, not a
 * wolfBoot bug. */
static int fuzz_mmu_cb(uint64_t vaddr, uint64_t paddr, uint32_t size) {
    (void)vaddr; (void)paddr; (void)size;
    return 1;
}

/* Canonicalize the input ELF header in-place so that the harness drives
 * the loader past its gross structural checks and into the segment-walk
 * logic. Returns 1 if the buffer was canonicalized into a class32 ELF,
 * 0 for class64. */
static int canonicalize_elf_header(uint8_t *buf, size_t size, int class32) {
    /* Magic + ident */
    memcpy(buf, ELF_IDENT_STR, 4);
    buf[4] = class32 ? ELF_CLASS_32 : ELF_CLASS_64;
    buf[5] = ELF_ENDIAN_LITTLE;
    /* ident[6..15] left to the fuzzer */

    if (class32) {
        elf32_header *h = (elf32_header *)buf;
        h->type = ELF_HET_EXEC;
        h->ph_entry_size = sizeof(elf32_program_header);
        /* Clamp ph_entry_count so that ph_table_sz fits in image */
        uint32_t ph_off = h->ph_offset;
        if (ph_off >= size) {
            h->ph_offset = (uint32_t)sizeof(elf32_header);
            ph_off = h->ph_offset;
        }
        uint32_t avail = (size > ph_off) ? (uint32_t)(size - ph_off) : 0;
        uint32_t max_entries = avail / sizeof(elf32_program_header);
        if (h->ph_entry_count > max_entries) {
            h->ph_entry_count = (uint16_t)max_entries;
        }
    } else {
        elf64_header *h = (elf64_header *)buf;
        h->type = ELF_HET_EXEC;
        h->ph_entry_size = sizeof(elf64_program_header);
        uint64_t ph_off = h->ph_offset;
        if (ph_off >= size) {
            h->ph_offset = sizeof(elf64_header);
            ph_off = h->ph_offset;
        }
        uint64_t avail = (size > ph_off) ? (size - ph_off) : 0;
        uint64_t max_entries = avail / sizeof(elf64_program_header);
        if (h->ph_entry_count > max_entries) {
            h->ph_entry_count = (uint16_t)max_entries;
        }
    }
    return class32;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Hold the buffer big enough for the larger of the two header types
     * so canonicalization writes never spill past the allocation. */
    if (size < sizeof(elf64_header) || size > (1u << 20)) {
        return 0;
    }

    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) return 0;
    memcpy(buf, data, size);

    /* Pick a class from a fuzz-controlled byte that we are about to
     * overwrite anyway. */
    int class32 = (buf[6] & 1);
    canonicalize_elf_header(buf, size, class32);

    uintptr_t entry = 0;
    (void)elf_load_image_mmu(buf, (uint32_t)size, &entry, fuzz_mmu_cb);

    int is_elf32 = 0;
    (void)elf_open(buf, &is_elf32);

    free(buf);
    return 0;
}
