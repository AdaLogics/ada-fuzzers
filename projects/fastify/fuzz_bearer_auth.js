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
const auth = require('../fastify-auth/auth');
const bearer_auth = require('../fastify-bearer-auth/index');
const generateRandomJson = require('./generator');
const v8 = require('v8');
const vm = require('vm');

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    let fastify = new Fastify();

    // Start the fastify web instance
    start_server();

    // Create http request to the fastify web instance
    fetch("https://localhost:12345/auth", { method: "GET" });

    // Shut down and clean up the fastify web instance
    stop_server();

    async function start_server() {
      // Register the fastify-auth and fastify-bearer-auth plugin
      await fastify
        .register(auth)
        .register(bearerAuthPlugin, generateRandomJson(data, 1))
        .after(() => {
          // Add preHandler hook to activate the bearer auth plugin through the auth plugin
          fastify.addHook('preHandler', fastify.auth([fastify.verifyBearerAuth]));
          // Set /auth request string route and activate the bearer auth plugin
          fastify.route({
            method: 'GET',
            url: '/auth',
            onRequest: fastify.auth([fastify.verifyBearerAuth]),
            handler: async (req, reply) => {
              return generateRandomJson(data, 5);
            }
          });
        });

      await fastify.listen({port: 12345}, (err) => {});
    }

    function stop_server() {
      fastify.close();
      fastify = null;

      // Invoke garbage collection
      v8.setFlagsFromString('--expose_gc');
      const gc = vm.runInNewContext('gc');
      gc();
    }
  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1);
}

const ignored = ['not a function'];
