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

/* libFuzzer harness for wolfBoot's GPT (GUID Partition Table) parser
 * (src/gpt.c). The bootloader reads partition layout from untrusted disk
 * media on disk-boot platforms (x86 FSP). Malformed protective-MBR or GPT
 * header sectors are an obvious parser attack surface.
 *
 * The first input byte selects between gpt_check_mbr_protective() and
 * gpt_parse_header(); the rest is consumed as one or more 512-byte
 * sectors, with extra bytes also fed to gpt_parse_partition() to exercise
 * entry parsing with attacker-chosen sizes.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "gpt.h"

#define SECTOR 512

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 + SECTOR) return 0;
    if (size > (1u << 16)) return 0;

    uint8_t sector[SECTOR];
    memcpy(sector, data + 1, SECTOR);

    if ((data[0] & 0x1) == 0) {
        uint32_t lba = 0;
        (void)gpt_check_mbr_protective(sector, &lba);
    } else {
        struct guid_ptable hdr;
        memset(&hdr, 0, sizeof(hdr));
        (void)gpt_parse_header(sector, &hdr);
    }

    /* Also exercise the partition-entry parser with whatever data remains. */
    size_t rem = size - 1 - SECTOR;
    if (rem > 0) {
        struct gpt_part_info part;
        memset(&part, 0, sizeof(part));
        uint32_t entry_size = (uint32_t)(rem > 1024 ? 1024 : rem);
        (void)gpt_parse_partition(data + 1 + SECTOR, entry_size, &part);
    }

    return 0;
}
