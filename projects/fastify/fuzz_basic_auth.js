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
const basic_auth = require('../fastify-basic-auth/index');
const v8 = require('v8');
const vm = require('vm');
const generateRandomJson = require('./generator');

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    const authenticate = generateRandomJson(data, -1);
    let fastify = new Fastify();


    // Start the fastify web instance
    start_server();

    // Create an http request to the fastify web instance
    fetch("https://localhost:12345/auth", {method: "GET"});

    // Shut down and clean up the fastify web instance
    stop_server();
  } catch (error) {
    if (!ignoredError(error)) throw error;
  }

  async function start_server() {
    async function validate (username, password, req, reply) { return done(); }

    // Register the fastify-auth and fastify-basic-auth plugin
    fastify
      .register(auth)
      .register(basic_auth, {validate, authenticate})
      .after(() => {
        // Add preHandler hook to activate the basic auth plugin through the auth plugin
        fastify.addHook('preHandler', fastify.auth([fastify.basicAuth]));
        // Set /auth request string route and activate the basic auth plugin
        fastify.route({
          method: 'GET',
          url: '/auth',
          onRequest: fastify.auth([fastify.basicAuth]),
          handler: async (req, reply) => {
            return generateRandomJson(data, 5);
          }
        });
      });

    await fastify.listen({port: 12345, host: "0.0.0.0"});
  }

  async function stop_server() {
    await fastify.close();
    fastify = null;

    // Invoke garbage collection
    v8.setFlagsFromString('--expose_gc');
    const gc = vm.runInNewContext('gc');
    gc();
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1);
}

const ignored = ['not a function'];
