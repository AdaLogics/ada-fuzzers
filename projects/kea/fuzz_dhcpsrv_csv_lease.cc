// Copyright 2025 Ada Logics Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
#include <config.h>

#include <asiolink/io_address.h>
#include <dhcp/duid.h>
#include <dhcpsrv/csv_lease_file4.h>
#include <dhcpsrv/csv_lease_file6.h>
#include <dhcpsrv/lease.h>
#include <dhcpsrv/testutils/lease_file_io.h>

using namespace isc;
using namespace isc::data;
using namespace isc::dhcp;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
	char filename[256];
	sprintf(filename, "/tmp/libfuzzer.%d", getpid());

	FILE *fp = fopen(filename, "wb");
	if (!fp)
		return 0;
	fwrite(Data, Size, 1, fp);
	fclose(fp);

    try {
        CSVLeaseFile4 lease_file(filename);
        lease_file.open(false);
        Lease4Ptr lease;
        lease_file.next(lease);
        lease_file.close();
    } catch (const std::exception&) {
      // ignore any errors
    }

    try {
        CSVLeaseFile6 lease_file(filename);
        lease_file.open(false);
        Lease6Ptr lease;
        lease_file.next(lease);
        lease_file.close();
    } catch (const std::exception&) {
        // ignore any errors
    }

    unlink(filename);
    return 0;
}
