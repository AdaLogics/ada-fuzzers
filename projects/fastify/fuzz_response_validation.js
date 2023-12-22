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
const validation = require('../fastify-response-validation/index');
const v8 = require('v8');
const vm = require('vm');

module.exports.fuzz = function(data) {
  try {
    const fastify_schema = {
      OSS: { type: 'number' },
      Fuzz: { type: 'string' }
    };
    const provider = new FuzzedDataProvider(data);
    let fastify = Fastify();
    validation(fastify, {}, () => {});

    const key = Reflect.ownKeys(fastify)
      .find(key => key.toString() === 'Symbol(fastify.hooks)')

    const routeOpts = new Object();
    const schema = new Object();
    const response = new Object();
    const content = new Object();
    const media = new Object();
    const innerSchema = new Object();
    innerSchema.schema = fastify_schema;
    media['OSS-Fuzz'] = innerSchema;
    content.content = media
    response[200] = content;
    schema.response = response;
    routeOpts.responseValidation = true;
    routeOpts.responseStatusCodeValidation  = provider.consumeBoolean();
    routeOpts.schema = schema;

    fastify[key].onRoute[0](routeOpts);

    const reply = new Object();
    reply.statusCode = provider.consumeIntegralInRange(100, 999);
    reply.getHeader = (a) => { return 'OSS-Fuzz' };
    reply.code = (a) => {};

    routeOpts.preSerialization[0](
      null, reply, provider.consumeRemainingAsString(), () => {}
    );

    fastify.close();
    fastify = null;

    // Invoke garbage collection
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
  'schema is invalid'
];
