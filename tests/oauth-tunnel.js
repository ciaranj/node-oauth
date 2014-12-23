var vows = require('vows'),
  assert = require('assert'),
  http = require('http'),
  net = require('net'),
  tunnel = require('../lib/tunnel'),
  OAuth= require('../lib/oauth'),
  OAuth2= require('../lib/oauth2');

var server = http.createServer(function(request, response) {}).listen(8081);

server.on('listening', function() {
    console.log('proxy started');    
});

server.on('connect', onConnect); // for v0.7 or later

// TUNNELING
function onConnect(req, clientSocket, head) {
  console.log('PROXY: got CONNECT request');
  console.log('PROXY: creating a tunnel');
  var serverSocket = net.connect(443, 'api.twitter.com', function() {
    console.log('PROXY: replying to client CONNECT request');
    clientSocket.write('HTTP/1.1 200 Connection established\r\n\r\n');
    clientSocket.pipe(serverSocket);
    serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    // workaround, see joyent/node#2524
    serverSocket.on('end', function() {
      clientSocket.end();
    });
  });
}

var twitterConsumerKey = 'gxLbZ89CCGHQQPDWZBAbbQ';
var twitterConsumerSecret = 'HNmpq2w7pBF3wLKi6qWUUsAw9iisWBMFuwZZpV2gR3w';

vows.describe('OAuth').addBatch({
  'tunnel with oauth2': {
    topic: function() {
      var oauth2 = new OAuth2.OAuth2(
        twitterConsumerKey, 
        twitterConsumerSecret, 
       'https://api.twitter.com/', 
       null,
       'oauth2/token', 
       null);

      oauth2.setTunnel({
        proxy: {
          host: '10.115.100.103', // your proxy address
          port: 8080
        }
      });

      oauth2.getOAuthAccessToken(
       '',
       {'grant_type':'client_credentials'},
       this.callback);      
    },
    'can be accessed': function (err, access_token, refresh_token, results) {
      console.log('bearer oauth2: ', access_token);
      assert.isNotNull(access_token);      
    }
  },
  'tunnel with oauth': {
    topic: function() {      
      var twitterAccessToken = '53659570-i6162HliVa0jDfT2pJGtfif51lHtZ1m7KarZJIBY';
      var twitterTokenSecret = 'a1fTxtYQFdyn3GSRnhOhNnHXAyiSpXo39KeW6OAoug';

      var oauth = new OAuth.OAuth(
        'https://api.twitter.com/oauth/request_token',
        'https://api.twitter.com/oauth/access_token',
        twitterConsumerKey,
        twitterConsumerSecret,
        '1.0A',
        null,
        'HMAC-SHA1',
        null,
        null);

      oauth.setTunnel({
        proxy: {
          host: '10.115.100.103', // your proxy address
          port: 8080
        }
      });

      oauth.get(
        'https://api.twitter.com/1.1/trends/place.json?id=23424977',
        twitterAccessToken, //test user token
        twitterTokenSecret, //test user secret            
        this.callback);
    },
    'can be accessed': function (err, data, res) {      
      console.log('bearer oauth: ', data);
      assert.isNotNull(data);
    }
  }

}).export(module);