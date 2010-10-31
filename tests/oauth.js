var vows = require('vows'),
    assert = require('assert'),
    OAuth= require('../lib/oauth').OAuth;

vows.describe('OAuth').addBatch({
    'When generating the signature base string described in http://oauth.net/core/1.0/#sig_base_example': {
        topic: new OAuth(null, null, null, null, null, null, "HMAC-SHA1"),
        'we get the expected result string': function (oa) {
          var result= oa._createSignatureBase("GET", "http://photos.example.net/photos", 
                                              "file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original")
          assert.equal( result, "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal");
        }
    },
    'When normalising a url': {
      topic: new OAuth(null, null, null, null, null, null, "HMAC-SHA1"),
      'default ports should be stripped': function(oa) {
        assert.equal( oa._normalizeUrl("https://somehost.com:443/foo/bar"), "https://somehost.com/foo/bar" );
      },
      'should leave in non-default ports from urls for use in signature generation': function(oa) {
        assert.equal( oa._normalizeUrl("https://somehost.com:446/foo/bar"), "https://somehost.com:446/foo/bar" );
        assert.equal( oa._normalizeUrl("http://somehost.com:81/foo/bar"), "http://somehost.com:81/foo/bar" );
      },
      'should add a trailing slash when no path at all is present': function(oa) {
        assert.equal( oa._normalizeUrl("http://somehost.com"),  "http://somehost.com/")
      }
    },
    'When signing a url': {
      topic: function() {
        var oa= new OAuth(null, null, "consumerkey", "consumersecret", "1.0", null, "HMAC-SHA1");
        oa._getTimestamp= function(){ return "1272399856"; }
        oa._getNonce= function(){ return "ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp"; }
        return oa;
      },
      'Provide a valid signature when no token present': function(oa) {
        assert.equal( oa.signUrl("http://somehost.com:3323/foo/poop?bar=foo"), "http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_version=1.0&oauth_signature=7ytO8vPSLut2GzHjU9pn1SV9xjc%3D");
      },
      'Provide a valid signature when a token is present': function(oa) {
        assert.equal( oa.signUrl("http://somehost.com:3323/foo/poop?bar=foo", "token"), "http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_token=token&oauth_version=1.0&oauth_signature=9LwCuCWw5sURtpMroIolU3YwsdI%3D");
      },
      'Provide a valid signature when a token and a token secret is present': function(oa) {
        assert.equal( oa.signUrl("http://somehost.com:3323/foo/poop?bar=foo", "token", "tokensecret"), "http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_token=token&oauth_version=1.0&oauth_signature=zeOR0Wsm6EG6XSg0Vw%2FsbpoSib8%3D");
      }
    },
    'When non standard ports are used': {
        topic: function() {
          var oa= new OAuth(null, null, null, null, null, null, "HMAC-SHA1"),
              mockProvider= {};
              
          mockProvider.request= function(method, path, headers) {
            assert.equal(headers.Host, "somehost.com:8080");
            return result= {addListener:function(){}, 
                            end:function(){},
                            socket: {addListener: function(){}}};
          }
          oa._createClient= function(port, host) { 
            assert.equal(port, '8080');
            assert.equal(host, 'somehost.com');
            return mockProvider; 
          }
          return oa;
        },
        'getProtectedResrouce should correctly define the host headers': function(oa) {
          oa.getProtectedResource("http://somehost.com:8080", "GET", "oauth_token", null, function(){require('sys').p('dddd')})
        }
    },
    'When building the OAuth Authorization header': {
      topic: new OAuth(null, null, null, null, null, null, "HMAC-SHA1"), 
      'All provided oauth arguments should be concatentated correctly' : function(oa) {
       var parameters= [
          ["oauth_timestamp",         "1234567"],
          ["oauth_nonce",             "ABCDEF"],
          ["oauth_version",           "1.0"],
          ["oauth_signature_method",  "HMAC-SHA1"],
          ["oauth_consumer_key",      "asdasdnm2321b3"]];
        assert.equal(oa._buildAuthorizationHeaders(parameters), 'OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"'); 
      },
      '*Only* Oauth arguments should be concatentated, others should be disregarded' : function(oa) {
       var parameters= [
          ["foo",         "2343"],
          ["oauth_timestamp",         "1234567"],
          ["oauth_nonce",             "ABCDEF"],
          ["bar",             "dfsdfd"],
          ["oauth_version",           "1.0"],
          ["oauth_signature_method",  "HMAC-SHA1"],
          ["oauth_consumer_key",      "asdasdnm2321b3"],
          ["foobar",      "asdasdnm2321b3"]];
        assert.equal(oa._buildAuthorizationHeaders(parameters), 'OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"'); 
      },
      '_buildAuthorizationHeaders should not depends on Array.prototype.toString' : function(oa) {
       var _toString = Array.prototype.toString;
       Array.prototype.toString = function(){ return '[Array] ' + this.length; }; // toString overwrite example used in jsdom.
       var parameters= [
          ["foo",         "2343"],
          ["oauth_timestamp",         "1234567"],
          ["oauth_nonce",             "ABCDEF"],
          ["bar",             "dfsdfd"],
          ["oauth_version",           "1.0"],
          ["oauth_signature_method",  "HMAC-SHA1"],
          ["oauth_consumer_key",      "asdasdnm2321b3"],
          ["foobar",      "asdasdnm2321b3"]];
        assert.equal(oa._buildAuthorizationHeaders(parameters), 'OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"');
       Array.prototype.toString = _toString;
      }
    },
    'When performing the Secure Request' : {
      topic: new OAuth("http://foo.com/RequestToken",
                       "http://foo.com/AccessToken",
                       "anonymous",  "anonymous",
                       "1.0A", "http://foo.com/callback", "HMAC-SHA1"),
      'using the POST method' : {
        'Any passed extra_params should form part of the POST body': function(oa) {
          var post_body_written= false;
          var op= oa._createClient;
          try {
            oa._createClient= function() {
              return {
                request: function(method, path, headers) {
                  return {
                    write: function(post_body){
                      post_body_written= true;
                      assert.equal(post_body,"scope=foobar%2C1%2C2");
                    },
                    socket: {addListener: function(){}},
                    addListener: function() {},
                    end: function() {}
                  }
                }
              }
            }
            oa._performSecureRequest("token", "token_secret", 'POST', 'http://foo.com/protected_resource', {"scope": "foobar,1,2"});
            assert.equal(post_body_written, true);
          }
          finally {
            oa._createClient= op;
          }
        }
      }
    },
    'When performing a secure' : {
      topic: new OAuth("http://foo.com/RequestToken",
                       "http://foo.com/AccessToken",
                       "anonymous",  "anonymous",
                       "1.0A", "http://foo.com/callback", "HMAC-SHA1"),
      'POST' : {
        'if no callback is passed' : {
          'it should return a request object': function(oa) {
            var request= oa.post("http://foo.com/blah", "token", "token_secret", "BLAH", "text/plain")
            assert.isObject(request);
            assert.equal(request.method, "POST");
            request.end();
          }
        },
        'if a callback is passed' : {
          "it should call the internal request's end method and return nothing": function(oa) {
            var callbackCalled= false;
            var op= oa._createClient;
            try {
              oa._createClient= function() {
                return {
                  request: function(method, path, headers) {
                    return {
                      write: function(){},
                      socket: {addListener: function(){}},
                      addListener: function() {},
                      end: function() {
                        callbackCalled= true;
                      }
                    }
                  }
                }
              }
              var request= oa.post("http://foo.com/blah", "token", "token_secret", "BLAH", "text/plain", function(e,d){})
              assert.equal(callbackCalled, true);
              assert.isUndefined(request);
            }
            finally {
              oa._createClient= op;
            }
          }
        },
        'if the post_body is not a string' : {
          "It should be url encoded and the content type set to be x-www-form-urlencoded" : function(oa) {
            var op= oa._createClient;
            try {
              var callbackCalled= false;
              oa._createClient= function() {
                return {
                  request: function(method, path, headers) {
                    assert.equal(headers["Content-Type"], "application/x-www-form-urlencoded")
                    return {
                      socket: {addListener: function(){}},
                      write: function(data) {
                          callbackCalled= true;
                          assert.equal(data, "foo=1%2C2%2C3&bar=1%2B2");
                       },
                      addListener: function() {},
                      end: function() {}
                    }
                  }
                }
              }
              var request= oa.post("http://foo.com/blah", "token", "token_secret", {"foo":"1,2,3", "bar":"1+2"})
              assert.equal(callbackCalled, true);
            }
            finally {
              oa._createClient= op;
            }
          }
        },
        'if the post_body is a string' : {
          "and no post_content_type is specified" : {
            "It should be written as is, with a content length specified, and the encoding should be set to be x-www-form-urlencoded" : function(oa) {
              var op= oa._createClient;
              try {
                var callbackCalled= false;
                 oa._createClient= function() {
                   return {
                     request: function(method, path, headers) {
                       assert.equal(headers["Content-Type"], "application/x-www-form-urlencoded");
                       assert.equal(headers["Content-length"], 23);
                       return {
                         socket: {addListener: function(){}},
                         write: function(data) {
                            callbackCalled= true;
                            assert.equal(data, "foo=1%2C2%2C3&bar=1%2B2");
                          },
                         addListener: function() {},
                         end: function() {}
                       }
                     }
                   }
                 }
                 var request= oa.post("http://foo.com/blah", "token", "token_secret", "foo=1%2C2%2C3&bar=1%2B2")
                 assert.equal(callbackCalled, true);
               }
               finally {
                 oa._createClient= op;
               }
             }
           },
           "and a post_content_type is specified" : {
             "It should be written as is, with a content length specified, and the encoding should be set to be as specified" : function(oa) {
               var op= oa._createClient;
               try { 
                 var callbackCalled= false;
                 oa._createClient= function() {
                   return {
                     request: function(method, path, headers) {
                       assert.equal(headers["Content-Type"], "unicorn/encoded");
                       assert.equal(headers["Content-length"], 23);
                       return {
                         socket: {addListener: function(){}},
                         write: function(data) {
                            callbackCalled= true;
                            assert.equal(data, "foo=1%2C2%2C3&bar=1%2B2");
                          },
                         addListener: function() {},
                         end: function() {}
                       }
                     }
                   }
                 }
                 var request= oa.post("http://foo.com/blah", "token", "token_secret", "foo=1%2C2%2C3&bar=1%2B2", "unicorn/encoded")
                 assert.equal(callbackCalled, true);
               }
               finally {
                 oa._createClient= op;
               }
             }
           }
         }
       },
       'GET' : {
         'if no callback is passed' : {
           'it should return a request object': function(oa) {
             var request= oa.get("http://foo.com/blah", "token", "token_secret")
             assert.isObject(request); 
             assert.equal(request.method, "GET");
             request.end();
           }
         },
         'if a callback is passed' : {
           "it should call the internal request's end method and return nothing": function(oa) {
             var callbackCalled= false;
             var op= oa._createClient;
             try {
               oa._createClient= function() {
                 return {
                   request: function(method, path, headers) {
                     return {
                       socket: {addListener: function(){}},
                       addListener: function() {},
                       end: function() {
                         callbackCalled= true;
                       }
                     }
                   }
                 }
               }
               var request= oa.get("http://foo.com/blah", "token", "token_secret", function(e,d) {})
               assert.equal(callbackCalled, true);
               assert.isUndefined(request);
             }
             finally {
               oa._createClient= op;
             }
           }
         },
       }
     }
}).export(module);
