/**
 * node-oauth-libre is a Node.js library for OAuth
 *
 * Copyright (C) 2010-2012 Ciaran Jessup
 * Copyright (C) 2016 Rudolf Olah
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

/**
 * Node OAuth Libre
 * @module oauth-libre
 */

/**
 * OAuth 1.0
 * @see OAuth
 */
exports.OAuth = require("./lib/oauth").OAuth;

/**
 * OAuth 1.0 Echo
 * @see OAuthEcho
 */
exports.OAuthEcho = require("./lib/oauth").OAuthEcho;

/**
 * OAuth 2.0
 * @see OAuth2
 */
exports.OAuth2 = require("./lib/oauth2").OAuth2;

/**
 * OAuth 1.0 with Promises interface instead of callbacks
 * @see OAuthPromise
 */
exports.PromiseOAuth = require("./lib/oauth-promise").OAuth;

/**
 * OAuth 2.0 with Promises interface instead of callbacks
 * @see OAuth2Promise
 */
exports.PromiseOAuth2 = require("./lib/oauth2-promise").OAuth2;
