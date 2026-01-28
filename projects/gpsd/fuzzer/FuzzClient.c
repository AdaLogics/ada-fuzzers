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

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "gpsd_config.h"
#include "gpsd.h"
#include "gps_json.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Production uses null-terminated buffers from recv() - replicate that here */
    char *input = (char *)malloc(Size + 1);
    if (!input) return 0;
    memcpy(input, Data, Size);
    input[Size] = '\0';

    /* Allocate structures for parsed data */
    struct gps_policy_t policy;
    struct devconfig_t devconf;
    memset(&policy, 0, sizeof(policy));
    memset(&devconf, 0, sizeof(devconf));

    /* Test json_watch_read() - parses ?WATCH command JSON */
    json_watch_read(input, &policy, NULL);

    /* Test json_device_read() - parses ?DEVICE command JSON */
    json_device_read(input, &devconf, NULL);

    /* Test ntrip_parse_url() - if device path was populated */
    if (strlen(devconf.path) > 0) {
        struct ntrip_stream_t stream;
        struct gpsd_errout_t errout;
        memset(&stream, 0, sizeof(stream));
        memset(&errout, 0, sizeof(errout));
        errout.debug = 0;
        ntrip_parse_url(&errout, &stream, devconf.path);
    }

    /* Test parse_uri_dest() - if device path was populated */
    if (strlen(policy.devpath) > 0) {
        char uri[GPS_PATH_MAX];
        char *h = NULL, *s = NULL, *d = NULL;
        strlcpy(uri, policy.devpath, sizeof(uri));
        parse_uri_dest(uri, &h, &s, &d);
    }

    free(input);
    return 0;
}
