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
const { fastifySecureSession } = require('../fastify-secure-session/index.js');
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
      secret: provider.consumeString(32),
      cookie: { path: '/' }
    }, () => {});
  } else {
    secureSession(fastify, {
      sessionName: 'session',
      cookieName: 'session',
      key: provider.consumeString(32),
      cookie: { path: '/' }
    }, () => {});
  }

  if (provider.consumeBoolean()) {
    if (typeof fastify.decodeSecureSession === 'function') {
      fastify.decodeSecureSession(provider.consumeRemainingAsString());
    }
  } else {
    if (typeof fastify.createSecureSession === 'function') {
      fastify.encodeSecureSession(fastify.createSecureSession(provider.consumeRemainingAsString()));
    }
  }

  // Invoke garbage collection
  fastify = null;
  v8.setFlagsFromString('--expose_gc');
  const gc = vm.runInNewContext('gc');
  gc();
};

