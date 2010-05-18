describe 'node-oauth'
  before_each
    OAuth= require('oauth').OAuth
  end
  describe 'Auth'
    describe 'OAuth'
      it 'should generate the signature base string described in http://oauth.net/core/1.0/#sig_base_example'
         oa= new OAuth(null, null, null, null, null, null, "HMAC-SHA1");
      
        var result= oa._createSignatureBase("GET", "http://photos.example.net/photos", 
                                            "file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original")
        result.should.eql "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
      end
      describe 'Url normalisation'
        before_each
         oa= new OAuth(null, null, null, null, null, null, "HMAC-SHA1");
        end
        it 'should strip default ports from urls for use in signature generation'
          oa._normalizeUrl("https://somehost.com:443/foo/bar").should_be "https://somehost.com/foo/bar"
        end
        it 'should leave in non-default ports from urls for use in signature generation'
          oa._normalizeUrl("https://somehost.com:446/foo/bar").should_be "https://somehost.com:446/foo/bar"
          oa._normalizeUrl("http://somehost.com:81/foo/bar").should_be "http://somehost.com:81/foo/bar"
        end
        it 'should ensure that there exists a trailing slash when no path at all is present'
          oa._normalizeUrl("http://somehost.com").should_be "http://somehost.com/"
        end
      end
      describe 'Url signing'
        it 'should provide a valid signature when no token present'
          oa= new OAuth(null, null, "consumerkey", "consumersecret", "1.0", null, "HMAC-SHA1");
          oa.stub('_getTimestamp').and_return("1272399856")
          oa.stub('_getNonce').and_return("ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp")
          oa.signUrl("http://somehost.com:3323/foo/poop?bar=foo").should_be ("http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_version=1.0&oauth_signature=7ytO8vPSLut2GzHjU9pn1SV9xjc%3D")
        end
        it 'should provide a valid signature when a token is present'
          oa= new OAuth(null, null, "consumerkey", "consumersecret", "1.0", null, "HMAC-SHA1");
          oa.stub('_getTimestamp').and_return("1272399856")
          oa.stub('_getNonce').and_return("ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp")
          oa.signUrl("http://somehost.com:3323/foo/poop?bar=foo", "token").should_be ("http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_token=token&oauth_version=1.0&oauth_signature=9LwCuCWw5sURtpMroIolU3YwsdI%3D")
        end
        it 'should provide a valid signature when a token and a token secret is present'
          oa= new OAuth(null, null, "consumerkey", "consumersecret", "1.0", null, "HMAC-SHA1");
          oa.stub('_getTimestamp').and_return("1272399856")
          oa.stub('_getNonce').and_return("ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp")
          oa.signUrl("http://somehost.com:3323/foo/poop?bar=foo", "token", "tokensecret").should_be ("http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_token=token&oauth_version=1.0&oauth_signature=zeOR0Wsm6EG6XSg0Vw%2FsbpoSib8%3D")
        end
      end
      describe 'host headers for non default ports should contain the port'
        describe 'when getProtectedResource is called'
          it 'should set the correct Host header when provided with an unusual port'
            oa2= new OAuth(null, null, null, null, null, null, "HMAC-SHA1");
            var mockProvider= {}, 
                mockRequest= {addListener:function(){},
                              end:function(){}};


            stub(mockProvider, 'request').and_return(mockRequest)
            mockProvider.should.receive('request', 'once').with_args('GET', an_instance_of(String), {Host:"somehost.com:8080"}) 
            stub(oa2, '_createClient').and_return(mockProvider)
            oa2.should.receive('_createClient', 'once') .with_args('8080', 'somehost.com') 
            
            oa2.getProtectedResource("http://somehost.com:8080", "GET", "oauth_token", null, function(){require('sys').p('dddd')})
          end
        end

        describe 'when getOAuthRequestToken is called'
          it 'should set the correct Host header when provided with an unusual port'
            oa2= new OAuth(null, null, null, null, null, null,  "HMAC-SHA1");
            var mockProvider= {}, 
                mockRequest= {addListener:function(){},
                              end:function(){}};

            stub(mockProvider, 'request').and_return(mockRequest)
            mockProvider.should.receive('request', 'once').with_args('GET', an_instance_of(String), {Host:"somehost.com:8080"})
            stub(oa2, '_createClient').and_return(mockProvider)
            oa2.should.receive('_createClient', 'once').with_args('8080', 'somehost.com')
            oa2.getProtectedResource("http://somehost.com:8080", "GET", "oauth_token", null, function(){})
          end
        end

        describe 'when getOauthAccessToken is called'
          it 'should set the correct Host header when provided with an unusual port'
            oa2= new OAuth(null, null, null, null, null, null, "HMAC-SHA1");
            var mockProvider= {}, 
                mockRequest= {addListener:function(){},
                              end:function(){}};

            stub(mockProvider, 'request').and_return(mockRequest)
            mockProvider.should.receive('request', 'once').with_args('GET', an_instance_of(String), {Host:"somehost.com:8080"})
            stub(oa2, '_createClient').and_return(mockProvider)
            oa2.should.receive('_createClient', 'once').with_args('8080', 'somehost.com')
            oa2.getProtectedResource("http://somehost.com:8080", "GET", "oauth_token", null, function(){})
          end
        end
      end 
    end
  end
end