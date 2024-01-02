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
const basic_auth = require('../fastify-basic-auth/index');
const bearer_auth = require('../fastify-bearer-auth/lib/verify-bearer-auth-factory');
const compare = require('../fastify-bearer-auth/lib/compare');
const key_authenticate = require('../fastify-bearer-auth/lib/authenticate');
const v8 = require('v8');
const vm = require('vm');

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    const choice = provider.consumeIntegralInRange(1, 4);
    const keys = new Set([provider.consumeString(64)]);
    const authFunction = () => { return provider.consumeBoolean(); };
    const payload = provider.consumeRemainingAsString();
    const authenticate = {realm: 'OSS-Fuzz'}
    const validate = (a, b, c, d, e) => {
      if (data.consumeBoolean()) {
        e();
      } else {
        e(new Error('FuzzError'));
      }
    };

    let fastify = Fastify();
    basic_auth(fastify, { validate, authenticate }, () => {});

    const req = new Object();
    const reply = new Object();
    const headers = new Object();
    headers['authorization'] = payload;
    req.headers = headers;

    const bearer_header = new Object();
    const raw_header = new Object();
    bearer_header.authorization = payload;
    raw_header.headers = bearer_header;
    req.raw = raw_header;

    const log = new Object();
    log['error'] = (a, b) => {};
    req.log = log;

    reply.header = (a, b) => {};
    reply.code = (a) => {};
    reply.send = (a) => {};

    switch (choice) {
      case 1:
        fastify.basicAuth(req, reply, () => {});
        break;
      case 2:
        bearer_auth({ keys: keys, auth: authFunction })(req, reply, () => {});
        break;
      case 3:
        compare(Buffer.from(payload, "utf-8"), Buffer.from(payload, "utf-8"));
        break;
      case 4:
        key_authenticate([Buffer.from(payload, "utf-8")], Buffer.from(payload, "utf-8"));
        break;
    }

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
  ''
];
