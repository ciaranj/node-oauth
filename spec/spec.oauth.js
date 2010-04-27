describe 'node-oauth'
  before_each
    OAuth= require('oauth').OAuth
    oa= new OAuth(null, null, null, null, null, "HMAC-SHA1");
  end
  describe 'Auth'
    describe 'OAuth'
      it 'should generate the signature base string described in http://oauth.net/core/1.0/#sig_base_example'
        var result= oa._createSignatureBase("GET", "http://photos.example.net/photos", 
                                            "file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original")
        result.should.eql "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
      end
      describe 'Url normalisation'
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
    end
  end
end