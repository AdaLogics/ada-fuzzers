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
const fastifyJwt = require('../fastify-jwt/jwt');
const v8 = require("v8");
const vm = require("vm");

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    const choice = provider.consumeIntegralInRange(1, 3);
    let fastify = new Fastify();

    fastifyJwt(fastify, { secret: 'FuzzSecret' }, () => {});

    let payload = provider.consumeRemainingAsString();

    if (payload) {
      switch (choice) {
        case 1:
          fastify.jwt.sign(payload);
          break;
        case 2:
          fastify.jwt.verify(payload);
          break;
        case 3:
          fastify.jwt.decode(payload);
          break;
      }
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
  'must be an object',
  'token is malformed',
  'token header is not a valid base64url'
];
