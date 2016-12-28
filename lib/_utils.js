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

/** @module OAuthUtils */

/**
 * Returns true if this is a host that closes *before* it ends?!?!
 *
 * @param {string} hostName
 * @return {boolean} True if the host name includes Google
 */
module.exports.isAnEarlyCloseHost = function(hostName) {
  return hostName && hostName.match(".*google(apis)?.com$");
};
