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
const fp = require('../fastify-plugin');
const fastifySecureSession = require('../fastify-secure-session/index.js');
const v8 = require('v8');
const vm = require('vm');

module.exports.fuzz = function(data) {
  const provider = new FuzzedDataProvider(data);
  let fastify = new Fastify();

  let secureSession = fp(fastifySecureSession, {
    fastify: '4.x',
    name: provider.consumeString(20)
  })

  if (provider.consumeBoolean()) {
    secureSession(fastify, {
      sessionName: 'session',
      cookieName: 'session',
      secret: 'ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFHIKLMNOPQRS',
      cookie: { path: '/' }
    }, () => {});
  } else {
    let ret = secureSession(fastify, {
      sessionName: 'session',
      cookieName: 'session',
      key: 'ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFHIKLMNOPQRS',
      cookie: { path: '/' }
    }, () => {});
  }

  const choice = provider.consumeIntegralInRange(1, 3);
  const payload = provider.consumeRemainingAsString();
  const key = Reflect.ownKeys(fastify)
    .find(key => key.toString() === 'Symbol(fastify.hooks)')

  const req = new Object();
  const reply = new Object();
  const cookies = new Object();
  reply.setCookie = (a, b, c) => {};
  cookies['session'] = payload;
  req.cookies = cookies

  switch (choice) {
    case 1:
      if (typeof fastify.decodeSecureSession === 'function') {
        fastify.decodeSecureSession(payload);
      }
      break;
    case 2:
      if (typeof fastify.encodeSecureSession === 'function') {
        fastify.encodeSecureSession(fastify.createSecureSession(payload));
      }
      break;
    case 3:
      if (typeof fastify[key].onRequest[0] === 'function') {
        fastify[key].onRequest[0](req, reply, () => {});
        fastify[key].onReply[0](req, reply, payload, () => {});
      }
      break;
  }

  // Invoke garbage collection
  fastify = null;
  v8.setFlagsFromString('--expose_gc');
  const gc = vm.runInNewContext('gc');
  gc();
};

