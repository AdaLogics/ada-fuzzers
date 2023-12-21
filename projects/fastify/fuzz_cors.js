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
const Vary = require('../fastify-cors/vary');
const Cors = require('../fastify-cors/index');
const v8 = require('v8');
const vm = require('vm');

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    const isArray = provider.consumeBoolean();
    const choice = provider.consumeIntegralInRange(1, 5);
    const payload = provider.consumeRemainingAsString();
    let fastify = new Fastify();

    // Initialise fake header and reply
    let header = new Object();
    const reply = new Object();

    if (isArray) {
      header = [payload, payload];
    } else {
      header = payload;
    }

    reply.getHeader = (a) => {return header;};
    reply.header = (a, b) => {};

    switch (choice) {
      case 1:
        Cors(fastify, null, () => {});
        break;
      case 2:
        Vary.createAddFieldnameToVary(payload)(reply);
        break;
      case 3:
        Vary.addOriginToVaryHeader()(reply);
        break;
      case 4:
        Vary.addAccessControlRequestHeadersToVaryHeader()(reply);
        break;
      case 5:
        Vary.parse(payload);
        break;
    }

    // Invoke garbage collection
    fastify = null;

    v8.setFlagsFromString('--expose_gc');
    const gc = vm.runInNewContext('gc');
    gc();
  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1);
}

const ignored = [
  'Cannot read properties',
  'contains invalid characters'
];
