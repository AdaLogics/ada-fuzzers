#!/bin/bash -eu
# Copyright 2025 Ada Logics Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Compile log4cplus
cd $SRC/log4cplus
./configure --prefix=/usr --enable-static --disable-shared --with-pic
make -j"$(nproc)"
make install

# Configure flags
cd $SRC/kea
export CXXFLAGS="${CXXFLAGS:-} -gdwarf-4"
export LDFLAGS="${LDFLAGS:-} -gdwarf-4"

CPP_ARGS="-stdlib=libc++  \
  -DCHRONO_SAME_DURATION=1 -D_LIBCPP_ENABLE_CXX17_REMOVED_AUTO_PTR \
  -D_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION -D_GLIBCXX_USE_DEPRECATED=1"
LD_ARGS="-stdlib=libc++"

if [ "$SANITIZER" = "coverage" ]; then
  CPP_ARGS="${CPP_ARGS} -fprofile-instr-generate -fcoverage-mapping"
fi

if [ "$SANITIZER" = "coverage" ] || [ "$SANITIZER" = "introspector" ] || [ "$SANITIZER" = "none" ]; then
  SANITIZER_CHOICE=
else
  SANITIZER_CHOICE="-D b_sanitize=${SANITIZER}"
  CPP_ARGS="${CPP_ARGS} -fsanitize=fuzzer-no-link"
fi

meson setup build --prefix="$OUT" $SANITIZER_CHOICE -D cpp_std=c++17 \
  -D fuzz=enabled -D tests=disabled -D crypto=openssl -D default_library=static \
  -D default_both_libraries=static -D cpp_args="$CPP_ARGS" -D cpp_link_args="$LD_ARGS" \
  -D postgresql=enabled -D mysql=enabled -D krb5=enabled
meson compile --verbose -C build

# Package static library
find $SRC/kea/build/src/lib -type f -name '*.o' -print0 | xargs -0 llvm-ar rcsD libkea.a
llvm-ranlib libkea.a

# Find necessary static libraries
BUILD_BASEDIR="$SRC/kea/build/src"
HOOKLIBS=$(find $BUILD_BASEDIR/hooks -type f -name '*.a' -print)
KEA_STATIC_LIBS="/usr/lib/liblog4cplus.a libkea.a $HOOKLIBS "
KEA_STATIC_LIBS+=$(find $BUILD_BASEDIR/bin \( -path '/src/kea/build/src/bin/dhcp4/*' -o -path '/src/kea/build/src/bin/dhcp6/*' \) -prune -o -type f -name '*.a' -print)

INCLUDES="-I. -I$SRC -I$SRC/kea-fuzzer -Isrc -Ibuild -Isrc/lib -Isrc/bin -Isrc/hooks -Isrc/hooks/d2 -Isrc/hooks/d2/gss_tsig "
INCLUDES+="-Isrc/hooks/dhcp/pgsql -Isrc/hooks/dhcp/mysql -I/usr/include/postgresql -I/usr/include/mariadb"
LIBS="-lpthread -ldl -lm -lc++ -lc++abi -lssl -lcrypto -lkrb5 -lgssapi_krb5"
export CXXFLAGS="${CXXFLAGS} -std=c++17 -stdlib=libc++ -Wno-unused-parameter -Wno-unused-value"

for fuzzer in fuzz_ioaddress fuzz_http fuzz_dhcpsrv fuzz_agent fuzz_d2 fuzz_util fuzz_cc fuzz_dhcpsrv_csv_lease fuzz_crypto fuzz_hook_tsig
do
  $CXX $CXXFLAGS "$SRC/kea-fuzzer/helper_func.cc" \
    "$SRC/kea-fuzzer/${fuzzer}.cc"  \
    -Wl,--start-group $KEA_STATIC_LIBS -Wl,--end-group  \
    $INCLUDES $LIBS $LIB_FUZZING_ENGINE -o "$OUT/${fuzzer}"

  if [ -f "$SRC/kea-fuzzer/${fuzzer}.dict" ]; then
    cp $SRC/kea-fuzzer/${fuzzer}.dict $OUT
  fi
done

for DHCPVER in 4 6
do
  for fuzzer in fuzz_dhcp_parser fuzz_eval fuzz_dhcp_pkt fuzz_pgsql fuzz_mysql
  do
    extra_lib=""
    case "$fuzzer" in fuzz_pgsql)
      extra_lib="$SRC/kea-fuzzer/pgmock.cc"
      ;;
    esac
    case "$fuzzer" in fuzz_mysql)
      extra_lib="$SRC/kea-fuzzer/mysqlmock.cc"
      ;;
    esac

    $CXX $CXXFLAGS "$SRC/kea-fuzzer/helper_func.cc" \
      "$SRC/kea-fuzzer/${fuzzer}${DHCPVER}.cc" $extra_lib \
      -Wl,--start-group $KEA_STATIC_LIBS $BUILD_BASEDIR/bin/dhcp$DHCPVER/libdhcp$DHCPVER.a \
      -Wl,--end-group $INCLUDES $LIBS \
      $LIB_FUZZING_ENGINE -o "$OUT/${fuzzer}${DHCPVER}"

    if [ -f "$SRC/kea-fuzzer/${fuzzer}.dict" ]; then
      cp $SRC/kea-fuzzer/${fuzzer}.dict $OUT/${fuzzer}${DHCPVER}.dict
    fi
  done
done

# Prepare the seeds
zip -j $OUT/fuzz_dhcpsrv_seed_corpus.zip $SRC/kea-fuzzer/corp/*.json
zip -j $OUT/fuzz_dhcp_parser4_seed_corpus.zip $SRC/kea-fuzzer/corp/*.json
zip -j $OUT/fuzz_dhcp_parser6_seed_corpus.zip $SRC/kea-fuzzer/corp/*.json
zip -j $OUT/fuzz_agent_seed_corpus.zip $SRC/kea/src/bin/agent/tests/testdata/*.json
zip -j $OUT/fuzz_d2_seed_corpus.zip $SRC/kea/src/bin/d2/tests/testdata/*.json

# Prepare for base databse file
mkdir -p $OUT/var/lib/kea/
touch $OUT/var/lib/kea/kea-leases4.csv
touch $OUT/var/lib/kea/kea-leases6.csv
