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
const fastJson = require('../fast-json-stringify/index')
const Location = require('../fast-json-stringify/lib/location');
const Validator = require('../fast-json-stringify/lib/validator');

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    const location = new Location();
    const validator = new Validator();
    const stringify = fastJson(generateRandomJson(provider.consumeBytes(provider.remainingBytes()), 5));
    const json = generateRandomJson(Buffer.from(provier.consumeRemaningAsBytes()), 5, true);

    switch (provider.consumeIntegralInRange(1, 7)) {
      case 1:
        validator.validate(json);
        break;
      case 2:
        validator.addSchema(json, '');
        break;
      case 3:
        validator.convertSchemaToAjvFormat(json);
        break;
      case 4:
        Validator.restoreFromState(json);
        break;
      case 5:
        location.getPropertyLocation(provider.consumeRemainingAsString());
        break;
      case 6:
        location.addMergedSchema(json, provider.consumeRemainingAsString());
        break;
      case 7:
        stringify(fastJson(generateRandomJson(provider.consumeRemainingAsBytes(), 5)));
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
  'schema is invalid',
  'Cannot read properties',
  'undefined or null',
  'cannot be converted',
  'not a function'
];
