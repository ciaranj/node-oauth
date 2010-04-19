describe 'node-oauth'
  before_each
    OAuth= require('oauth').OAuth
  end
  describe 'Auth'
    describe 'OAuth'
      it 'should generate the signature base string described in http://oauth.net/core/1.0/#sig_base_example'
        var result= new OAuth()._createSignatureBase("GET", "http://photos.example.net/photos", 
                                            "file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original")
        result.should.eql "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
      end
    end
  end
end