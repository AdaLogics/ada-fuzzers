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
const { fastifyCookie } = require('../fastify-cookie/plugin.js');
const v8 = require('v8');
const vm = require('vm');

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    let fastify = new Fastify();

    fastifyCookie(fastify, { secret: provider.consumeString(20) }, () => {});

    switch (provider.consumeIntegralInRange(1, 4)) {
      case 1:
        fastify.serializeCookie(provider.consumeRemainingAsString(), provider.consumeRemainingAsString());
        break;
      case 2:
        fastify.signCookie(provider.consumeRemainingAsString());
        break;
      case 3:
        fastify.unsignCookie(provider.consumeRemainingAsString());
        break;
      case 4:
        fastify.parseCookie(provider.consumeRemainingAsString());
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
  'argument name is invalid'
];
