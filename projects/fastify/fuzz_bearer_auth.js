// Copyright 2023 Ada Logics Ltd.
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
'use strict'

const { FuzzedDataProvider } = require('@jazzer.js/core');
const Fastify = require('./fastify');
const bearer_auth = require('../fastify-bearer-auth/index');
const v8 = require('v8');
const vm = require('vm');

module.exports.fuzz = function(data) {
  const provider = new FuzzedDataProvider(data);
  let fastify = new Fastify();

  bearer_auth(fastify, {
    addHook: false,
    verifyErrorLogLevel: false,
    auth: (a, b) => { return provider.consumeBoolean(); }
  }, () => {});

  if (typeof fastify.verifyBearerAuth === 'function') {
    let request = {
      raw: {headers: {authorization: provider.consumeRemainingAsString()}}
    }
    let reply = {
      header: (a, b) => { done(); },
      code: (a) => { done(); },
      send: (a) => { done(); },
    }
    if (request.raw.headers.authorization) {
      fastify.verifyBearerAuth(request, reply, () => {});
    }
  }

  // Invoke garbage collection
  fastify = null;
  v8.setFlagsFromString('--expose_gc');
  const gc = vm.runInNewContext('gc');
  gc();
}
