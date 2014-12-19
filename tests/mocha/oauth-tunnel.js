describe('tunnel with oauth',function() {
  var http = require('http');
  var net = require('net');
  var OAuth= require('../../lib/oauth');
  var OAuth2= require('../../lib/oauth2');


  // CREATE PROXY
  before(function(done){    

    var server = http.createServer(function(request, response) {

    }).listen(8081);

    server.on('listening', function() {
        console.log('proxy started');
        done();
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
  });

  it('oauth1 trends Twitter API v1.1',function(done) {    
    var twitterConsumerKey = '';
    var twitterConsumerSecret = '';
    var twitterAccessToken = '';
    var twitterTokenSecret = '';

    var oauth = new OAuth.OAuth(
      'https://api.twitter.com/oauth/request_token',
      'https://api.twitter.com/oauth/access_token',
      twitterConsumerKey,
      twitterConsumerSecret,
      '1.0A',
      null,
      'HMAC-SHA1',
      null,
      null,
      {
        proxy: {
            host: '127.0.0.1', // PUT PROXY ADDRESS
            port: 8081
        }
      }
    );
    oauth.get(
      'https://api.twitter.com/1.1/trends/place.json?id=23424977',
      twitterAccessToken, //test user token
      twitterTokenSecret, //test user secret            
      function (e, data, res){
        if (e) console.error(e);        
        console.log(require('util').inspect(data));
        done();      
      });    
  });

  it('oauth2 gets bearer token', function(done) {

     var twitterConsumerKey = '';
     var twitterConsumerSecret = '';
     var oauth2 = new OAuth2.OAuth2(twitterConsumerKey, twitterConsumerSecret, 
       'https://api.twitter.com/', 
       null,
       'oauth2/token', 
       null,
       {
          proxy: {
              host: '127.0.0.1', // your proxy address
              port: 8081
          }
        }
       );
     oauth2.getOAuthAccessToken(
       '',
       {'grant_type':'client_credentials'},
       function (e, access_token, refresh_token, results){      
       console.log('bearer: ',access_token);
       done();
     });

      this.timeout(200000);


  
   });

});   