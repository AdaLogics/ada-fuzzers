#!/bin/bash -eu
# Copyright 2023 Ada Logics Ltd.
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

# Install dependencies
cd $SRC/fast-json-stringify
npm install

cd $SRC/secure-json-parse
npm install

cd $SRC/fastify-jwt
npm install

cd $SRC/fastify-cors
npm install

cd $SRC/fastify-response-validation
npm install

cd $SRC/fastify-cookie
npm install

cd $SRC/fast-content-type-parse
npm install

cd $SRC/fastify-basic-auth
npm install

cd $SRC/fastify-bearer-auth
npm install

cd $SRC/fastify-plugin
npm install

cd $SRC/fastify-secure-session
npm install

cd $SRC/fastify
npm install
npm install --save-dev @jazzer.js/core

# Clean base fastify
rm -rf $OUT/fastify

# Copy Fasity plugin
cp -r $SRC/fast-json-stringify $OUT/
cp -r $SRC/fastify-jwt $OUT/
cp -r $SRC/fastify-cors $OUT/
cp -r $SRC/fastify-response-validation $OUT/
cp -r $SRC/secure-json-parse $OUT/
cp -r $SRC/fastify-cookie $OUT/
cp -r $SRC/fast-content-type-parse $OUT/
cp -r $SRC/fastify-auth $OUT/
cp -r $SRC/fastify-basic-auth $OUT/
cp -r $SRC/fastify-bearer-auth $OUT/
cp -r $SRC/fastify-plugin $OUT/
cp -r $SRC/fastify-secure-session $OUT/


# Build fuzzers
compile_javascript_fuzzer fastify fuzz_json.js -i fast-json-stringify --sync
compile_javascript_fuzzer fastify fuzz_jwt.js -i fastify-jwt --sync
compile_javascript_fuzzer fastify fuzz_cors.js -i fastify-cors --sync
compile_javascript_fuzzer fastify fuzz_response_validation.js -i fastify-response-validation --sync
compile_javascript_fuzzer fastify fuzz_cookie.js -i fastify-cookie --sync
compile_javascript_fuzzer fastify fuzz_ct_parse.js -i fast-content-type-parse --sync
compile_javascript_fuzzer fastify fuzz_auth.js -i fastify --sync
compile_javascript_fuzzer fastify fuzz_secure_session.js -i fastify-secure-session --sync
