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

var events = require("events");

exports.DummyResponse = function(statusCode) {
  this.statusCode = statusCode;
  this.headers = {};
};

exports.DummyResponse.prototype = events.EventEmitter.prototype;

exports.DummyResponse.prototype.setEncoding = function() {
};

exports.DummyRequest = function(response) {
  this.response = response;
  this.responseSent = false;
};

exports.DummyRequest.prototype = events.EventEmitter.prototype;

exports.DummyRequest.prototype.write = function(postBody) {
  this.responseSent = true;
  this.emit("response", this.response);
};

exports.DummyRequest.prototype.end = function() {
  if (!this.responseSent) {
    this.responseSent = true;
    this.emit("response",this.response);
  }
  this.response.emit("end");
};
