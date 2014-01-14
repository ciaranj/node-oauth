describe('OAuth1.0',function(){
  var OAuth= require('../lib/oauth');
  var OAuth2= require('../lib/oauth2');

  it('tests trends Twitter API v1.1',function(done){
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
            port: 8080
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

  it('gets bearer token', function(done){    
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
              port: 8080
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
   });

});   