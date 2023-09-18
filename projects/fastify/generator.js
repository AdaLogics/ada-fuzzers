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
const { FuzzedDataProvider } = require('@jazzer.js/core');
const choices = ["number", "string", "boolean", "array", "object"];
const leaf_choices = ["number", "string", "boolean"];
const object_choices = ["boolean", "object"];

// Max width for array and objects
const MAX_WIDTH = 5;

// Max depth for the generated Json
const MAX_DEPTH = 5;

// Function to generate random json object for fuzzers
const generateRandomJson = (data, max_depth, object = false) => {
  const provider = new FuzzedDataProvider(data);
  if (max_depth > MAX_DEPTH){
    max_depth = MAX_DEPTH;
  }

  // Randomly choose a element type
  var choice = null;
  if (object) {
    // Create random Json with root element of boolean or Json Object only
    choice = provider.pickValue(object_choices);
  } else if (max_depth <= 0) {
    // Ignore Json Object and Json Array which would increase the json depth
    choice = provider.pickValue(leaf_choices);
  } else {
    choice = provider.pickValue(choices);
  }

  if (choice == "number") {
    return randomNumber();
  }
  if (choice == "string") {
    return randomString();
  }
  if (choice == "boolean") {
    return randomBoolean();
  }
  if (choice == "array") {
    return randomArray();
  }
  if (choice == "object") {
    return randomObject();
  }

  function randomNumber() {
    // Generate random integer with at most 6 bytes (maximum)
    return provider.consumeIntegral(6);
  }

  function randomString() {
    // Generate random string with at most all of the remaining bytes
    return provider.consumeString(provider.remainingBytes());
  }

  function randomBoolean() {
    // Generate random boolean
    return provider.consumeBoolean();
  }

  function randomArray() {
    // Generate random json array object with 1 ~ MaxWidth elements recursively
    var array = [];

    for (var i = 0; i < provider.consumeIntegralInRange(1, MAX_WIDTH); i++) {
      array[i] = generateRandomJson(Buffer.from(provider.consumeRemainingAsBytes()), max_depth - 1);
    }

    return array;
  }

  function randomObject() {
    // Generate random json object with 1 ~ MaxWidth elements recursively
    var object = {};

    for (var i = 0; i < provider.consumeIntegralInRange(1, MAX_WIDTH); i++) {
      var key = provider.consumeString(provider.consumeIntegralInRange(1, MAX_WIDTH));
      object[key] = generateRandomJson(Buffer.from(provider.consumeRemainingAsBytes()), max_depth - 1);
    }

    return object;
  }
}

module.exports = generateRandomJson
