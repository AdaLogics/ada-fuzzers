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
const generateRandomJson = require('./generator');
const v8 = require("v8");
const vm = require("vm");

module.exports.fuzz = function(data) {
  const provider = new FuzzedDataProvider(data);
  const choice = provider.consumeIntegralInRange(1, 3);
  const param = generateRandomJson(data, 5);
  let fastify = new Fastify();

  fastify.register(fastifyJwt, {
    secret: 'FuzzSecret'
  })

  fastify.post('/sign', async function (req, reply) {
    fastify.jwt.sign(param)
    reply.send('')
  })
  fastify.post('/decode', async function (req, reply) {
    fastify.jwt.decode(param)
    reply.send('')
  })
  fastify.post('/verify', async function (req, reply) {
    fastify.jwt.verify(param)
    reply.send('')
  })

  start_server();

  switch (choice) {
    case 1:
      fetch("https://localhost:12345/sign", { method: "POST" });
      break;
    case 2:
      fetch("https://localhost:12345/decode", { method: "POST" });
      break;
    case 3:
      fetch("https://localhost:12345/verify", { method: "POST" });
      break;
  }

  stop_server();

  async function start_server() {
    await fastify.listen(
      { port: 12345, host: '0.0.0.0'},
      (err, address) => {}
    )
  }

  function stop_server() {
    fastify.close();
    fastify = null;

    // Invoke garbage collection
    v8.setFlagsFromString('--expose_gc');
    const gc = vm.runInNewContext('gc');
    gc();
  }
};
