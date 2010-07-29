var sys= require('sys')

var OAuth= require('../lib/oauth').OAuth;

var oa= new OAuth("http://term.ie/oauth/example/request_token.php?foo=bar",
                  "http://term.ie/oauth/example/access_token.php",
                  "key",
                  "secret",
                  "1.0",
                  null,
                  "PLAINTEXT")

oa.getOAuthRequestToken(function(error, oauth_token, oauth_token_secret,  results){
  if(error) sys.puts('error :' + error)
  else { 
    sys.puts('oauth_token :' + oauth_token)
    sys.puts('oauth_token_secret :' + oauth_token_secret)
    sys.puts('requestoken results :' + sys.inspect(results))
    sys.puts("Requesting access token")
    oa.getOAuthAccessToken(oauth_token, oauth_token_secret, function(error, oauth_access_token, oauth_access_token_secret, results2) {
      sys.puts('oauth_access_token :' + oauth_access_token)
      sys.puts('oauth_token_secret :' + oauth_access_token_secret)
      sys.puts('accesstoken results :' + sys.inspect(results2))
      sys.puts("Requesting access token")
      var data= "";
      oa.getProtectedResource("http://term.ie/oauth/example/echo_api.php?foo=bar&too=roo", "GET", oauth_access_token, oauth_access_token_secret,  function (error, data, response) {
          sys.puts(data);
      });
    });
  }
})