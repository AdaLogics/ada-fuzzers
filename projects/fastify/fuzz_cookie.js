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
const { parse, serialize } = require('../fastify-cookie/cookie');
const { sign, unsign, Signer } = require('../fastify-cookie/signer');

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    const choice = provider.consumeIntegralInRange(1, 6);
    const secret = provider.consumeString(64);
    const payload = provider.consumeRemainingAsString();

    switch (choice) {
      case 1:
        Signer([secret]).sign(payload);
        break;
      case 2:
        Signer([secret]).unsign(payload);
        break;
      case 3:
        sign(payload, secret);
        break;
      case 4:
        unsign(payload, secret);
        break;
      case 5:
        parse(payload);
        break;
      case 6:
        serialize(secret, payload);
        break;
    }

  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1);
}

const ignored = [
  'Cookie value must be provided as a string',
  'Signed cookie string must be provided',
  'not supported',
  'Secret key must be a string or Buffer',
  'Invalid digest',
  'argument name is invalid',
  'argument val is invalid'
];
