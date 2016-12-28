/**
 * node-oauth-libre is a Node.js library for OAuth
 *
 * Copyright (C) 2010-2012 Ciaran Jessup
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

var vows = require("vows");
var assert = require("assert");
var sha1 = require("../lib/sha1");

vows.describe("SHA1 Hashing").addBatch({
  "When using the SHA1 Hashing function": {
    topic: sha1,
    "we get the specified digest as described in http://oauth.net/core/1.0/#sig_base_example (A.5.2)": function (sha1Object) {
      var result = sha1Object.hmacsha1(
        "kd94hf93k423kf44&pfkkdhi9sl3r4s00",
        "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal");
      var expected = "tR3+Ty81lMeYAr/Fid0kMTYa/WM=";
      assert.equal(result, expected);
    }
  }
}).export(module);
