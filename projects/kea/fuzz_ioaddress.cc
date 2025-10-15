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
#include <cstddef>
#include <cstdint>
#include <string>

#include <asiolink/io_address.h>
#include <asiolink/io_error.h>

using isc::asiolink::IOAddress;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string s(reinterpret_cast<const char*>(data), size);

  try {
    IOAddress addr(s);
    addr.toText();
    addr.isV4();
    addr.isV6();
    addr.getFamily();
    addr.toBytes();

    std::vector<uint8_t> bytes = addr.toBytes();
    IOAddress::fromBytes(addr.getFamily(), &bytes[0]);
  } catch (const std::exception&) {
    // Catch exceptions
  }

  return 0;
}
