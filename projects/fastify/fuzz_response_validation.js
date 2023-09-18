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
const generateRandomJson = require('./generator');

module.exports.fuzz = function(data) {
  const provider = new FuzzedDataProvider(data);
  let fastify = new Fastify();

  fastify.register(validation);

  // Set validation route
  var fastify_schema = generateRandomJson(data, 5);
  fastify.route({
    method: 'GET',
    path: '/',
    schema: fastify_schema,
    handler: async (req, reply) => {
      return generateRandomJson(data, -1);
    }
  })

  fastify.inject({
    method: 'GET',
    path: '/'
  }, (err, res) => {});

  fastify.close();
  fastify = null;

  // Invoke garbage collection
  v8.setFlagsFromString('--expose_gc');
  const gc = vm.runInNewContext('gc');
  gc();
};
