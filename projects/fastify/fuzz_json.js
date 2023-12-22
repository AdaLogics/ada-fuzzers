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
const SchemaValidator = require('../fast-json-stringify/lib/schema-validator');
const Serializer = require('../fast-json-stringify/lib/serializer');
const Validator = require('../fast-json-stringify/lib/validator');
const { parse, safeParse, scan } = require('../secure-json-parse/index');

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    const choice = provider.consumeIntegralInRange(1, 22);
    const location = new Location();
    const serializer = new Serializer();
    const validator = new Validator();
    const string = provider.consumeRemainingAsString();
    const bytes = new TextEncoder().encode(string);
    const json = generateRandomJson(Buffer.from(bytes), 5, true);

    switch (choice) {
      case 1:
        validator.validate(json, json);
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
        location.getPropertyLocation(string);
        break;
      case 6:
        location.addMergedSchema(json, string);
        break;
      case 7:
        SchemaValidator(json);
        break;
      case 8:
        SchemaValidator(bytes);
        break;
      case 9:
        SchemaValidator(string);
        break;
      case 10:
        serializer.asInteger(string);
        break;
      case 11:
        serializer.asNumber(string);
        break;
      case 12:
        serializer.asBoolean(string);
        break;
      case 13:
        serializer.asDateTime(string);
        break;
      case 14:
        serializer.asDate(string);
        break;
      case 15:
        serializer.asTime(string);
        break;
      case 16:
        serializer.asString(string);
        break;
      case 17:
        serializer.asStringSmall(string);
        break;
      case 18:
        Serializer.restoreFromState(json);
        break;
      case 19:
        fastJson(json)();
        break;
      case 20:
        parse(string);
        break;
      case 21:
        safeParse(string);
        break;
      case 22:
        scan(json);
        break;
    }
  } catch (error) {
    if (!(error instanceof SyntaxError)) {
      if (!ignoredError(error)) throw error;
    }
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
  'type must be JSONType',
  'NOT SUPPORTED'
];
