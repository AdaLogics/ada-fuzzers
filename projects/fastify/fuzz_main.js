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
const generateRandomJson = require('./generator');
const SIZE = 512;
const v8 = require('v8');
const vm = require('vm');

module.exports.fuzz = function(data) {
  const provider = new FuzzedDataProvider(data);
  let fastify = require('./fastify')({logger: false});
  let req = {
    schema: {
      body: {
        type: 'object',
        properties: generateRandomJson(Buffer.from(provider.consumeBytes(SIZE)), 3)
      },
      querystring: {
        type: 'object',
        properties: generateRandomJson(Buffer.from(provider.consumeBytes(SIZE)), 3)
      },
      params: {
        type: 'object',
        properties: generateRandomJson(Buffer.from(provider.consumeBytes(SIZE)), 3)
      },
      headers: {
        type: 'object',
        properties: generateRandomJson(Buffer.from(provider.consumeBytes(SIZE)), 3)
      }
    }
  };
  let res = {
    schema: {
      response: {
        200: {
          type: 'object',
          properties: generateRandomJson(Buffer.from(provider.consumeBytes(SIZE)), 3)
        }
      }
    }
  };

  fastify.post('/', req, async (request, reply) => { return done(); });
  fastify.get('/', res, async (request, reply) => {
    return generateRandomJson(Buffer.from(provider.consumeBytes(SIZE)), -1);
  });

  start_server();

  fetch("https://localhost:12345", { method: "GET" });
  fetch("https://localhost:12345", {
    method: "POST",
    body: JSON.stringify(generateRandomJson(Buffer.from(provider.consumeBytes(SIZE)), 3)),
    headers: generateRandomJson(Buffer.from(provider.consumeBytes(SIZE)), 3),
    querystring: generateRandomJson(Buffer.from(provider.consumeBytes(SIZE)), 3),
    params: generateRandomJson(Buffer.from(provider.consumeBytes(SIZE)), 3)
  });

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
    req = null;
    res = null;

    // Invoke garbage collection
    v8.setFlagsFromString('--expose_gc');
    const gc = vm.runInNewContext('gc');
    gc();
  }
}

function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1);
}

const ignored = ['not a function'];
