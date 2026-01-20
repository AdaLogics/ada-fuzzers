/* Copyright 2026 Google LLC
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

#define kMinInputLength 3
#define kMaxInputLength 16384

// Global session for reuse across fuzzer iterations
static struct gps_device_t session;
static struct gps_context_t context;
static int pipe_fds[2] = {-1, -1};

// Minimal error output callback (suppress all output)
static void null_errout(const char *s)
{
    (void)s;
    // Suppress all debug output during fuzzing
}

// Initialize fuzzer - called once before fuzzing starts
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    // Create a pipe for feeding fuzzer data to gpsd_poll()
    if (pipe(pipe_fds) < 0) {
        return -1;
    }

    // Set read end to non-blocking (packet_get1 expects non-blocking)
    int flags = fcntl(pipe_fds[0], F_GETFL, 0);
    if (flags < 0 || fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }

    // Use PRODUCTION initialization functions
    gps_context_init(&context, "fuzz");
    gpsd_init(&session, &context, "/dev/fuzz");

    // Override error output to suppress logs
    context.errout.debug = 0;
    context.errout.report = null_errout;

    // Set file descriptor to our pipe
    session.gpsdata.gps_fd = pipe_fds[0];

    return 0;
}

// Main fuzzing entry point - uses PRODUCTION gpsd_poll() directly
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < kMinInputLength || Size > kMaxInputLength) {
        return 0;
    }

    // Clear driver state between iterations for stateless fuzzing
    // Note: gpsd_clear() intentionally preserves device_type and last_controller
    // because production gpsd_activate() needs them after clearing driver data.
    // For stateless fuzzing, we must clear these manually to avoid dangling pointers.
    gpsd_clear(&session);
    session.device_type = NULL;
    session.last_controller = NULL;

    // Restore file descriptor (gpsd_clear resets some fields)
    session.gpsdata.gps_fd = pipe_fds[0];

    // Randomize readonly/passive
    context.readonly = (Data[0] & 0x01);
    context.passive = (Data[1] & 0x01);

    // Write fuzzer data to pipe
    ssize_t written = write(pipe_fds[1], Data + 2, Size - 2);
    if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        return 0;
    }

    // Call PRODUCTION entry point repeatedly to process all packets
    // First call: device_type=NULL → packet_get1() → auto-detection
    // Subsequent calls: device_type=SET → device_type->get_packet() → driver-specific
    // This tests both code paths within a single stateless iteration
    int max_iterations = 100; // Prevent infinite loops
    while (max_iterations-- > 0) {
        gps_mask_t changed = gpsd_poll(&session);
        // Stop if no more data available or error
        if (changed == 0 || changed == ERROR_SET) {
            break;
        }
    }

    return 0;
}
