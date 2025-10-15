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
#include "helper_func.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <unistd.h>

namespace fs = std::filesystem;

using namespace isc::data;

namespace fuzz {
    std::string writeTempConfig(bool isV4) {
        return writeTempFile(isV4? JSON_CONFIG4 : JSON_CONFIG6);
    }

    std::string writeTempFile(const std::string& payload, const char* suffix) {
        const long r = std::rand();
        const pid_t pid = ::getpid();

        std::string path = std::string("/tmp/kea_fuzz_") + std::to_string(pid) +
                           "_" + std::to_string(r) + "." + (suffix ? suffix : "tmp");

        std::ofstream ofs(path.c_str(), std::ios::binary);
        if (ofs.good()) {
            ofs.write(payload.data(), static_cast<std::streamsize>(payload.size()));
            ofs.close();
            return path;
        }
        return std::string();
    }

    void deleteTempFile(std::string file_path) {
        if (fs::exists(file_path)) {
            try {
                fs::remove(file_path);
            } catch (...) {
                // Slient exceptions
            }
        }
    }

    isc::data::ElementPtr parseJSON(const std::string& s) {
        try {
            return Element::fromJSON(s);
        } catch (...) {
            return Element::createMap();
        }
    }
}
