/* Copyright 2026 Ada Logics Ltd.
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

/*
 * FuzzDriversStructured - Structured fuzzing harness for gpsd
 *
 * This harness performs protocol-aware fuzzing by constructing valid
 * protocol packets with correct checksums from fuzzer input data.
 * This enables deeper coverage of protocol-specific parsing code.
 */

#include "gpsd_config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "gpsd.h"

#define kMinInputLength 4
#define kMaxInputLength 8192

// Safety cap for satellites_visible - matches MAXCHANNELS in gps.h
#define MAX_SATS 184

// Protocol type selectors
#define PROTO_SIRF      0
#define PROTO_UBX       1
#define PROTO_ZODIAC    2
#define PROTO_GEOSTAR   3
#define PROTO_NAVCOM    4
#define PROTO_NMEA      5
#define PROTO_RTCM3     6
#define PROTO_TSIP      7
#define PROTO_GREIS     8
#define PROTO_SKYTRAQ   9
#define PROTO_COUNT     10

// Global session for reuse across fuzzer iterations
static struct gps_device_t session;
static struct gps_context_t context;
static int pipe_fds[2] = {-1, -1};

// Packet buffer for constructing protocol messages
static unsigned char packet_buf[kMaxInputLength + 256];

static void null_errout(const char *s)
{
    (void)s;
}

// SiRF checksum: 15-bit sum of payload bytes
static uint16_t sirf_checksum(const uint8_t *payload, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += payload[i];
    }
    return (uint16_t)(sum & 0x7fff);
}

// UBX Fletcher-8 checksum
static void ubx_checksum(const uint8_t *data, size_t len, uint8_t *ck_a, uint8_t *ck_b)
{
    *ck_a = 0;
    *ck_b = 0;
    for (size_t i = 0; i < len; i++) {
        *ck_a += data[i];
        *ck_b += *ck_a;
    }
}

// Zodiac checksum: negated sum of 16-bit words
static uint16_t zodiac_checksum(const uint16_t *words, size_t count)
{
    uint16_t sum = 0;
    for (size_t i = 0; i < count; i++) {
        sum += words[i];
    }
    return (uint16_t)(-sum);
}

// GeoStar checksum: XOR of 32-bit words
static uint32_t geostar_checksum(const uint8_t *data, size_t len)
{
    uint32_t cs = 0;
    for (size_t i = 0; i + 3 < len; i += 4) {
        uint32_t word = (uint32_t)data[i] |
                       ((uint32_t)data[i+1] << 8) |
                       ((uint32_t)data[i+2] << 16) |
                       ((uint32_t)data[i+3] << 24);
        cs ^= word;
    }
    return cs;
}

// Navcom checksum: XOR of bytes
static uint8_t navcom_checksum(const uint8_t *data, size_t len)
{
    uint8_t cs = 0;
    for (size_t i = 0; i < len; i++) {
        cs ^= data[i];
    }
    return cs;
}

// NMEA checksum: XOR of bytes between $ and *
static uint8_t nmea_checksum(const uint8_t *data, size_t len)
{
    uint8_t cs = 0;
    for (size_t i = 0; i < len; i++) {
        cs ^= data[i];
    }
    return cs;
}

// Skytraq checksum: XOR of payload bytes
static uint8_t skytraq_checksum(const uint8_t *data, size_t len)
{
    uint8_t cs = 0;
    for (size_t i = 0; i < len; i++) {
        cs ^= data[i];
    }
    return cs;
}

// Build a SiRF packet: 0xA0 0xA2 <len:2> <payload> <csum:2> 0xB0 0xB3
static size_t build_sirf_packet(const uint8_t *data, size_t len, uint8_t *out)
{
    if (len > 1023) len = 1023;  // SiRF max payload

    out[0] = 0xA0;
    out[1] = 0xA2;
    out[2] = (uint8_t)((len >> 8) & 0x07);  // Length high (3 bits)
    out[3] = (uint8_t)(len & 0xFF);          // Length low
    memcpy(out + 4, data, len);

    uint16_t cs = sirf_checksum(data, len);
    out[4 + len] = (uint8_t)(cs >> 8);
    out[5 + len] = (uint8_t)(cs & 0xFF);
    out[6 + len] = 0xB0;
    out[7 + len] = 0xB3;

    return 8 + len;
}

// Build a UBX packet: 0xB5 0x62 <class> <id> <len:2> <payload> <ck_a> <ck_b>
static size_t build_ubx_packet(const uint8_t *data, size_t len, uint8_t *out)
{
    if (len < 2) return 0;
    if (len > 8192) len = 8192;

    uint8_t msg_class = data[0];
    uint8_t msg_id = data[1];
    size_t payload_len = len - 2;

    out[0] = 0xB5;
    out[1] = 0x62;
    out[2] = msg_class;
    out[3] = msg_id;
    out[4] = (uint8_t)(payload_len & 0xFF);
    out[5] = (uint8_t)((payload_len >> 8) & 0xFF);

    if (payload_len > 0) {
        memcpy(out + 6, data + 2, payload_len);
    }

    uint8_t ck_a, ck_b;
    ubx_checksum(out + 2, 4 + payload_len, &ck_a, &ck_b);
    out[6 + payload_len] = ck_a;
    out[7 + payload_len] = ck_b;

    return 8 + payload_len;
}

// Build a Zodiac packet: 0xFF 0x81 <id:2> <ndata:2> <flags:2> <hsum:2> <data> <dsum:2>
static size_t build_zodiac_packet(const uint8_t *data, size_t len, uint8_t *out)
{
    if (len < 2) return 0;

    uint16_t msg_id = data[0] | ((uint16_t)data[1] << 8);
    size_t ndata = (len - 2) / 2;  // Number of 16-bit words
    if (ndata > 100) ndata = 100;

    out[0] = 0xFF;
    out[1] = 0x81;
    out[2] = (uint8_t)(msg_id & 0xFF);
    out[3] = (uint8_t)((msg_id >> 8) & 0xFF);
    out[4] = (uint8_t)(ndata & 0xFF);
    out[5] = (uint8_t)((ndata >> 8) & 0xFF);
    out[6] = 0x00;  // flags
    out[7] = 0x00;

    // Header checksum (words 0-3)
    uint16_t hsum = zodiac_checksum((uint16_t*)out, 4);
    out[8] = (uint8_t)(hsum & 0xFF);
    out[9] = (uint8_t)((hsum >> 8) & 0xFF);

    // Copy data words
    size_t data_bytes = ndata * 2;
    if (len >= 2 + data_bytes) {
        memcpy(out + 10, data + 2, data_bytes);
    } else {
        memset(out + 10, 0, data_bytes);
        if (len > 2) {
            memcpy(out + 10, data + 2, len - 2);
        }
    }

    // Data checksum
    uint16_t dsum = zodiac_checksum((uint16_t*)(out + 10), ndata);
    out[10 + data_bytes] = (uint8_t)(dsum & 0xFF);
    out[11 + data_bytes] = (uint8_t)((dsum >> 8) & 0xFF);

    return 12 + data_bytes;
}

// Build a GeoStar packet: 'P' 'S' 'G' 'G' <id:2> <len:2> <data> <checksum:4>
static size_t build_geostar_packet(const uint8_t *data, size_t len, uint8_t *out)
{
    if (len < 2) return 0;

    uint16_t msg_id = data[0] | ((uint16_t)data[1] << 8);
    size_t nwords = (len - 2) / 4;  // Number of 32-bit words
    if (nwords > 100) nwords = 100;

    out[0] = 'P';
    out[1] = 'S';
    out[2] = 'G';
    out[3] = 'G';
    out[4] = (uint8_t)(msg_id & 0xFF);
    out[5] = (uint8_t)((msg_id >> 8) & 0xFF);
    out[6] = (uint8_t)(nwords & 0xFF);
    out[7] = (uint8_t)((nwords >> 8) & 0xFF);

    size_t data_bytes = nwords * 4;
    if (len >= 2 + data_bytes) {
        memcpy(out + 8, data + 2, data_bytes);
    } else {
        memset(out + 8, 0, data_bytes);
        if (len > 2) {
            memcpy(out + 8, data + 2, len - 2);
        }
    }

    // Checksum covers header + data
    size_t cs_len = 8 + data_bytes;
    uint32_t cs = geostar_checksum(out, cs_len);
    out[cs_len] = (uint8_t)(cs & 0xFF);
    out[cs_len + 1] = (uint8_t)((cs >> 8) & 0xFF);
    out[cs_len + 2] = (uint8_t)((cs >> 16) & 0xFF);
    out[cs_len + 3] = (uint8_t)((cs >> 24) & 0xFF);

    return cs_len + 4;
}

// Build a Navcom packet: 0x02 0x99 0x66 <id> <len:2> <data> <checksum> 0x03
static size_t build_navcom_packet(const uint8_t *data, size_t len, uint8_t *out)
{
    if (len < 1) return 0;
    if (len > 1000) len = 1000;

    uint8_t msg_id = data[0];
    size_t payload_len = len - 1;

    out[0] = 0x02;
    out[1] = 0x99;
    out[2] = 0x66;
    out[3] = msg_id;
    out[4] = (uint8_t)((payload_len >> 8) & 0xFF);
    out[5] = (uint8_t)(payload_len & 0xFF);

    if (payload_len > 0) {
        memcpy(out + 6, data + 1, payload_len);
    }

    // Checksum covers ID and payload
    uint8_t cs = navcom_checksum(out + 3, 3 + payload_len);
    out[6 + payload_len] = cs;
    out[7 + payload_len] = 0x03;  // ETX

    return 8 + payload_len;
}

// Build an NMEA sentence with checksum
static size_t build_nmea_packet(const uint8_t *data, size_t len, uint8_t *out)
{
    // List of NMEA sentence types to use
    static const char *nmea_types[] = {
        "GPGGA", "GPRMC", "GPGLL", "GPGSA", "GPGSV", "GPVTG", "GPZDA",
        "GPGBS", "GPGST", "GPGRS", "GNGNS", "GPDTM", "GPTXT",
        "GLGSA", "GLGSV", "GAGSA", "GAGSV", "GBGSA", "GBGSV",
        "HCHDG", "SDDBT", "SDDPT", "WIMWV", "GPROT", "GPTHS"
    };
    static const size_t num_types = sizeof(nmea_types) / sizeof(nmea_types[0]);

    if (len < 1) return 0;

    // Use first byte to select sentence type
    size_t type_idx = data[0] % num_types;
    const char *sentence_type = nmea_types[type_idx];

    // Build the sentence body from remaining data
    out[0] = '$';
    size_t pos = 1;

    // Copy sentence type
    size_t type_len = strlen(sentence_type);
    memcpy(out + pos, sentence_type, type_len);
    pos += type_len;

    // Add comma-separated fields from fuzzer data
    for (size_t i = 1; i < len && pos < kMaxInputLength - 10; i++) {
        if (data[i] == '\r' || data[i] == '\n' || data[i] == '*') {
            out[pos++] = ',';  // Replace invalid chars with comma
        } else if (data[i] >= 32 && data[i] < 127) {
            out[pos++] = data[i];
        } else {
            out[pos++] = ',';
        }
    }

    // Compute checksum
    uint8_t cs = nmea_checksum(out + 1, pos - 1);

    // Add checksum and line ending
    out[pos++] = '*';
    static const char hex[] = "0123456789ABCDEF";
    out[pos++] = hex[(cs >> 4) & 0x0F];
    out[pos++] = hex[cs & 0x0F];
    out[pos++] = '\r';
    out[pos++] = '\n';

    return pos;
}

// Build an RTCM3 packet: 0xD3 <len:2> <data> <crc24:3>
// CRC-24Q is used for RTCM3
static uint32_t crc24q_hash(const uint8_t *data, size_t len)
{
    static const uint32_t crc24q_table[256] = {
        0x000000, 0x864CFB, 0x8AD50D, 0x0C99F6, 0x93E6E1, 0x15AA1A, 0x1933EC, 0x9F7F17,
        0xA18139, 0x27CDC2, 0x2B5434, 0xAD18CF, 0x3267D8, 0xB42B23, 0xB8B2D5, 0x3EFE2E,
        0xC54E89, 0x430272, 0x4F9B84, 0xC9D77F, 0x56A868, 0xD0E493, 0xDC7D65, 0x5A319E,
        0x64CFB0, 0xE2834B, 0xEE1ABD, 0x685646, 0xF72951, 0x7165AA, 0x7DFC5C, 0xFBB0A7,
        0x0CD1E9, 0x8A9D12, 0x8604E4, 0x00481F, 0x9F3708, 0x197BF3, 0x15E205, 0x93AEFE,
        0xAD50D0, 0x2B1C2B, 0x2785DD, 0xA1C926, 0x3EB631, 0xB8FACA, 0xB4633C, 0x322FC7,
        0xC99F60, 0x4FD39B, 0x434A6D, 0xC50696, 0x5A7981, 0xDC357A, 0xD0AC8C, 0x56E077,
        0x681E59, 0xEE52A2, 0xE2CB54, 0x6487AF, 0xFBF8B8, 0x7DB443, 0x712DB5, 0xF7614E,
        0x19A3D2, 0x9FEF29, 0x9376DF, 0x153A24, 0x8A4533, 0x0C09C8, 0x00903E, 0x86DCC5,
        0xB822EB, 0x3E6E10, 0x32F7E6, 0xB4BB1D, 0x2BC40A, 0xAD88F1, 0xA11107, 0x275DFC,
        0xDCED5B, 0x5AA1A0, 0x563856, 0xD074AD, 0x4F0BBA, 0xC94741, 0xC5DEB7, 0x43924C,
        0x7D6C62, 0xFB2099, 0xF7B96F, 0x71F594, 0xEE8A83, 0x68C678, 0x645F8E, 0xE21375,
        0x15723B, 0x933EC0, 0x9FA736, 0x19EBCD, 0x8694DA, 0x00D821, 0x0C41D7, 0x8A0D2C,
        0xB4F302, 0x32BFF9, 0x3E260F, 0xB86AF4, 0x2715E3, 0xA15918, 0xADC0EE, 0x2B8C15,
        0xD03CB2, 0x567049, 0x5AE9BF, 0xDCA544, 0x43DA53, 0xC596A8, 0xC90F5E, 0x4F43A5,
        0x71BD8B, 0xF7F170, 0xFB6886, 0x7D247D, 0xE25B6A, 0x641791, 0x688E67, 0xEEC29C,
        0x3347A4, 0xB50B5F, 0xB992A9, 0x3FDE52, 0xA0A145, 0x26EDBE, 0x2A7448, 0xAC38B3,
        0x92C69D, 0x148A66, 0x181390, 0x9E5F6B, 0x01207C, 0x876C87, 0x8BF571, 0x0DB98A,
        0xF6092D, 0x7045D6, 0x7CDC20, 0xFA90DB, 0x65EFCC, 0xE3A337, 0xEF3AC1, 0x69763A,
        0x578814, 0xD1C4EF, 0xDD5D19, 0x5B11E2, 0xC46EF5, 0x42220E, 0x4EBBF8, 0xC8F703,
        0x3F964D, 0xB9DAB6, 0xB54340, 0x330FBB, 0xAC70AC, 0x2A3C57, 0x26A5A1, 0xA0E95A,
        0x9E1774, 0x185B8F, 0x14C279, 0x928E82, 0x0DF195, 0x8BBD6E, 0x872498, 0x016863,
        0xFAD8C4, 0x7C943F, 0x700DC9, 0xF64132, 0x693E25, 0xEF72DE, 0xE3EB28, 0x65A7D3,
        0x5B59FD, 0xDD1506, 0xD18CF0, 0x57C00B, 0xC8BF1C, 0x4EF3E7, 0x426A11, 0xC426EA,
        0x2AE476, 0xACA88D, 0xA0317B, 0x267D80, 0xB90297, 0x3F4E6C, 0x33D79A, 0xB59B61,
        0x8B654F, 0x0D29B4, 0x01B042, 0x87FCB9, 0x1883AE, 0x9ECF55, 0x9256A3, 0x141A58,
        0xEFAAFF, 0x69E604, 0x657FF2, 0xE33309, 0x7C4C1E, 0xFA00E5, 0xF69913, 0x70D5E8,
        0x4E2BC6, 0xC8673D, 0xC4FECB, 0x42B230, 0xDDCD27, 0x5B81DC, 0x57182A, 0xD154D1,
        0x26359F, 0xA07964, 0xACE092, 0x2AAC69, 0xB5D37E, 0x339F85, 0x3F0673, 0xB94A88,
        0x87B4A6, 0x01F85D, 0x0D61AB, 0x8B2D50, 0x145247, 0x921EBC, 0x9E874A, 0x18CBB1,
        0xE37B16, 0x6537ED, 0x69AE1B, 0xEFE2E0, 0x709DF7, 0xF6D10C, 0xFA48FA, 0x7C0401,
        0x42FA2F, 0xC4B6D4, 0xC82F22, 0x4E63D9, 0xD11CCE, 0x575035, 0x5BC9C3, 0xDD8538
    };

    uint32_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc = ((crc << 8) & 0xFFFFFF) ^ crc24q_table[(crc >> 16) ^ data[i]];
    }
    return crc;
}

static size_t build_rtcm3_packet(const uint8_t *data, size_t len, uint8_t *out)
{
    if (len > 1023) len = 1023;  // RTCM3 max payload

    out[0] = 0xD3;
    out[1] = (uint8_t)((len >> 8) & 0x03);  // High 2 bits of length
    out[2] = (uint8_t)(len & 0xFF);          // Low 8 bits

    memcpy(out + 3, data, len);

    // CRC-24Q covers preamble + length + data
    uint32_t crc = crc24q_hash(out, 3 + len);
    out[3 + len] = (uint8_t)((crc >> 16) & 0xFF);
    out[4 + len] = (uint8_t)((crc >> 8) & 0xFF);
    out[5 + len] = (uint8_t)(crc & 0xFF);

    return 6 + len;
}

// Build a TSIP packet: DLE <id> <data with DLE stuffing> DLE ETX
static size_t build_tsip_packet(const uint8_t *data, size_t len, uint8_t *out)
{
    if (len < 1) return 0;

    uint8_t msg_id = data[0];
    size_t pos = 0;

    out[pos++] = 0x10;  // DLE
    out[pos++] = msg_id;

    // Copy payload with DLE stuffing
    for (size_t i = 1; i < len && pos < kMaxInputLength - 4; i++) {
        if (data[i] == 0x10) {
            out[pos++] = 0x10;  // Stuff DLE
        }
        out[pos++] = data[i];
    }

    out[pos++] = 0x10;  // DLE
    out[pos++] = 0x03;  // ETX

    return pos;
}

// Build a GREIS packet: <id:2> <data> <checksum> CR LF
static size_t build_greis_packet(const uint8_t *data, size_t len, uint8_t *out)
{
    if (len < 2) return 0;
    if (len > 200) len = 200;

    // Standard GREIS message IDs
    static const char *greis_ids[] = {"RE", "ER", "PM", "RC", "RD", "SI", "EL"};
    static const size_t num_ids = sizeof(greis_ids) / sizeof(greis_ids[0]);

    size_t id_idx = data[0] % num_ids;
    out[0] = greis_ids[id_idx][0];
    out[1] = greis_ids[id_idx][1];

    size_t payload_len = len - 2;
    if (payload_len > 0) {
        memcpy(out + 2, data + 2, payload_len);
    }

    // Simple XOR checksum for GREIS
    uint8_t cs = 0;
    for (size_t i = 0; i < 2 + payload_len; i++) {
        cs ^= out[i];
    }
    out[2 + payload_len] = cs;
    out[3 + payload_len] = '\r';
    out[4 + payload_len] = '\n';

    return 5 + payload_len;
}

// Build a Skytraq packet: 0xA0 0xA1 <len:2> <payload> <checksum> 0x0D 0x0A
static size_t build_skytraq_packet(const uint8_t *data, size_t len, uint8_t *out)
{
    if (len > 1000) len = 1000;

    out[0] = 0xA0;
    out[1] = 0xA1;
    out[2] = (uint8_t)((len >> 8) & 0xFF);
    out[3] = (uint8_t)(len & 0xFF);

    memcpy(out + 4, data, len);

    uint8_t cs = skytraq_checksum(data, len);
    out[4 + len] = cs;
    out[5 + len] = 0x0D;
    out[6 + len] = 0x0A;

    return 7 + len;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    if (pipe(pipe_fds) < 0) {
        return -1;
    }

    int flags = fcntl(pipe_fds[0], F_GETFL, 0);
    if (flags < 0 || fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }

    // Also make write end non-blocking
    flags = fcntl(pipe_fds[1], F_GETFL, 0);
    if (flags >= 0) {
        fcntl(pipe_fds[1], F_SETFL, flags | O_NONBLOCK);
    }

    gps_context_init(&context, "fuzz_structured");
    gpsd_init(&session, &context, "/dev/fuzz_structured");

    context.errout.debug = 0;
    context.errout.report = null_errout;

    // Set fd BEFORE gpsd_clear so pps_thread.devicefd gets correct value
    session.gpsdata.gps_fd = pipe_fds[0];

    // Set sourcetype to PIPE to prevent NTP/PPS code paths from activating
    // (see ntpshm_link_activate which skips pipes)
    session.sourcetype = SOURCE_PIPE;

    return 0;
}

// Drain any leftover data from the pipe
static void drain_pipe(int fd)
{
    unsigned char buf[4096];
    while (read(fd, buf, sizeof(buf)) > 0) {
        // Keep reading until empty
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < kMinInputLength || Size > kMaxInputLength) {
        return 0;
    }

    // Drain any leftover data from previous iteration
    drain_pipe(pipe_fds[0]);

    // Set fd before gpsd_clear so pps_thread gets correct value
    session.gpsdata.gps_fd = pipe_fds[0];

    gpsd_clear(&session);
    session.device_type = NULL;
    session.last_controller = NULL;

    // Ensure sourcetype stays set to prevent NTP/PPS activation
    session.sourcetype = SOURCE_PIPE;

    // Clear satellite data to prevent out-of-bounds access in fill_dop
    // when satellites_visible gets corrupted by fuzzer-generated data
    session.gpsdata.satellites_visible = 0;
    gpsd_zero_satellites(&session.gpsdata);

    // First byte selects protocol type
    uint8_t proto_type = Data[0] % PROTO_COUNT;

    // Second byte provides additional control
    context.readonly = (Data[1] & 0x01);
    context.passive = (Data[1] & 0x02);

    // Build protocol-specific packet from remaining data
    size_t packet_len = 0;
    const uint8_t *payload = Data + 2;
    size_t payload_len = Size - 2;

    switch (proto_type) {
    case PROTO_SIRF:
        packet_len = build_sirf_packet(payload, payload_len, packet_buf);
        break;
    case PROTO_UBX:
        packet_len = build_ubx_packet(payload, payload_len, packet_buf);
        break;
    case PROTO_ZODIAC:
        packet_len = build_zodiac_packet(payload, payload_len, packet_buf);
        break;
    case PROTO_GEOSTAR:
        packet_len = build_geostar_packet(payload, payload_len, packet_buf);
        break;
    case PROTO_NAVCOM:
        packet_len = build_navcom_packet(payload, payload_len, packet_buf);
        break;
    case PROTO_NMEA:
        packet_len = build_nmea_packet(payload, payload_len, packet_buf);
        break;
    case PROTO_RTCM3:
        packet_len = build_rtcm3_packet(payload, payload_len, packet_buf);
        break;
    case PROTO_TSIP:
        packet_len = build_tsip_packet(payload, payload_len, packet_buf);
        break;
    case PROTO_GREIS:
        packet_len = build_greis_packet(payload, payload_len, packet_buf);
        break;
    case PROTO_SKYTRAQ:
        packet_len = build_skytraq_packet(payload, payload_len, packet_buf);
        break;
    default:
        return 0;
    }

    if (packet_len == 0) {
        return 0;
    }

    // Write constructed packet to pipe
    ssize_t written = write(pipe_fds[1], packet_buf, packet_len);
    if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        return 0;
    }

    // Process packets
    int max_iterations = 100;
    while (max_iterations-- > 0) {
        gps_mask_t changed = gpsd_poll(&session);
        if (changed == 0 || changed == ERROR_SET) {
            break;
        }
    }

    return 0;
}
