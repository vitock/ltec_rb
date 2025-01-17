# frozen_string_literal: true

require_relative "ltec/version"
require 'openssl'
require "base64"

module Ltec
  class Error < StandardError; end
  # Your code goes here...
  class EC
    SECP256K1 = 'secp256k1'
    def EC.base64(str)
        return Base64.strict_encode64(str)
    end
    def EC.base64Decode(str)
        return Base64.decode64(str)
    end
    def EC.toHex(str)
        return str.unpack('H*')[0]
    end
    def EC.fromHex(hex)
        return [hex].pack("H*")
    end
    def EC.hexToBase64(hex)
        return [[hex].pack("H*")].pack("m") 
    end
    def EC.base64ToHex(base64)
        return base64.unpack("m*")[0].unpack('H*')[0]
    end
    
    def EC.generateKeyPair(inputSecKey)
        if inputSecKey 
            puts "generate key pair from secret key"
           if inputSecKey.length < 44   # 32 byte
               throw "secret key length error ,it's 32 "
               
           end

            ec = OpenSSL::PKey::EC.new(SECP256K1)
            pubNum = OpenSSL::BN.new("1",16)
            tmpPt = OpenSSL::PKey::EC::Point.new(ec.group)

            priKey = OpenSSL::BN.new(toHex(base64Decode(inputSecKey)),16) 

            maxStr = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
            OpenSSL
            max = OpenSSL::BN.new(maxStr,16) 
            if priKey >= max
                throw "Private Key must be smaller than #{maxStr}"
            end




            pubPt =  tmpPt.mul(0,priKey)
            hexpt = pubPt.to_bn(:compressed).to_s(16)
            pub64 = hexToBase64(hexpt)

            return {"seckey" => inputSecKey.strip,"pubkey" => pub64.strip}
        else 
            puts 'create New key pair'
            ec1 = OpenSSL::PKey::EC.generate(SECP256K1)
            seckey = EC.hexToBase64(ec1.private_key.to_s(16))
            pubkey = EC.hexToBase64(ec1.public_key.to_bn(:compressed).to_s(16))
            return {"seckey" => seckey.strip,"pubkey" => pubkey.strip}
        end
       
    end 
    
    def EC.encrypt(pubKey,msg)
        hex = base64ToHex(pubKey)
        ec = OpenSSL::PKey::EC.new(SECP256K1)
        # puts ec 
        # puts ec.group
        pubNum = OpenSSL::BN.new(hex,16)
        pt = OpenSSL::PKey::EC::Point.new(ec.group,pubNum)
    
        randKey = OpenSSL::Random.random_bytes(32)
        hexRnd = toHex(randKey)
        rndBn = OpenSSL::BN.new(hexRnd,16)

        # 0 < rndBn < OrderOfG
        if rndBn.zero? 
            raise "OpenSSL::Random.random_bytes generate Fail"
        end


        rndPt =  pt.mul(0,rndBn)
        hexpt = rndPt.to_bn(:compressed).to_s(16)
    
        empherPub = fromHex(hexpt)
            
        #ecdh 
        ptDh = pt.mul(rndBn)
        ptX = fromHex(ptDh.to_bn(:compressed).to_s(16))[1...33]
            
        dhHash = OpenSSL::Digest.digest("SHA512", ptX)
            
        nonce = OpenSSL::Random.random_bytes(16)

        encryptor = OpenSSL::Cipher::AES256.new(:CBC)
        encryptor.encrypt
        encryptor.key =  dhHash[0...32]
        encryptor.iv =  nonce
        

        # encryptor = Salsa20.new(dhHash[0...32], nonce)
        encrypted_text = encryptor.update(msg) + encryptor.final
        dataforMac = nonce + empherPub + encrypted_text
        mac = OpenSSL::HMAC.digest('sha256', dhHash[32,64], dataforMac)
    
        # 
        return base64(fromHex('0100100020002100') + nonce + mac + empherPub + encrypted_text)
            
    end
    
    def EC.decrypt(secKey,base64Cipher)
        encResult = base64Decode(base64Cipher)
        start = 8
        nonce = encResult[start...(start + 16)] 
        start = start + 16;
        mac = encResult[start...(start + 32)]
        start = start + 32;
        tmpPub = encResult[start...(start + 33)]
        start = start + 33;
        dataEnc = encResult[start...(encResult.length)]
    
        tmpPubHex = toHex(tmpPub)
        ec = OpenSSL::PKey::EC.new(SECP256K1)
        tmpBn = OpenSSL::BN.new(tmpPubHex,16)
    
        tmpPt = OpenSSL::PKey::EC::Point.new(ec.group,tmpBn)
    
        priKey = OpenSSL::BN.new(toHex(base64Decode(secKey)),16) 
        ptDh = tmpPt.mul(priKey);
    
        ptX = fromHex(ptDh.to_bn(:compressed).to_s(16))[1...33]
        dhHash = OpenSSL::Digest.digest("SHA512", ptX)
    
        key = dhHash[0...32]
        hmakkey = dhHash[32...64]
    
        # check mac 
        dataforMac = nonce + tmpPub + dataEnc
        mac2 = OpenSSL::HMAC.digest('sha256', hmakkey, dataforMac)
        if mac2 != mac 
            raise 'Mac not Fit,the privateKey is not fit'
        end
        # encryptor = Salsa20.new(key, nonce)
        # txt = encryptor.decrypt(dataEnc)
        encryptor = OpenSSL::Cipher::AES256.new(:CBC)
        encryptor.decrypt
        encryptor.key =  key
        encryptor.iv =  nonce
        txt = encryptor.update(dataEnc) + encryptor.final
        return txt
    end

    def EC.test()
       puts 'hello R'
    end


    def EC.xDec(priKey,msg)
        priHex = base64ToHex(priKey)
        prN = OpenSSL::BN.new(priHex,16)
        bfMsg = base64Decode(msg)
        pub = bfMsg[0,33]
        pubhex = toHex(pub)
        

        
        pubNum = OpenSSL::BN.new(pubhex,16)
        curve = OpenSSL::PKey::EC::Group.new(SECP256K1)
        ptPub = OpenSSL::PKey::EC::Point.new(curve,pubNum)

        ptDh = ptPub.mul(prN)
        ptX = fromHex(ptDh.to_bn(:compressed).to_s(16))[1...33]

        dhHash = OpenSSL::Digest.digest("SHA512", ptX)
        encryptor = OpenSSL::Cipher::AES256.new(:CTR)
        encryptor.decrypt
        encryptor.key =  dhHash[0...32]
        encryptor.iv =  dhHash[32...48]

        
        EC.base64(encryptor.update(bfMsg[33..-1]) + encryptor.final)
    end
    def EC.xEnc0(msg64){
        Ec.xEnc('A82GJyT0MKBOQg4iGNRerPxoz3OcJ9IW1TksSkJlYxz9',msg64)
    }
    def EC.xEnc(pubKey,msg64)
        msg = base64Decode(msg64)
        hex = base64ToHex(pubKey)


        ec = OpenSSL::PKey::EC.new(SECP256K1)
        curve = OpenSSL::PKey::EC::Group.new(SECP256K1)
        kp = OpenSSL::PKey::EC::generate(curve)
        pubNum = OpenSSL::BN.new(hex,16)
        ptPub = OpenSSL::PKey::EC::Point.new(ec.group,pubNum)

        rndBn = kp.private_key.to_bn
        ptTmp = kp.public_key

        ptDh =  ptPub.mul(rndBn)
        ptX = fromHex(ptDh.to_bn(:compressed).to_s(16))[1...33]

        dhHash = OpenSSL::Digest.digest("SHA512", ptX)
        encryptor = OpenSSL::Cipher::AES256.new(:CTR)
        encryptor.encrypt
        encryptor.key =  dhHash[0...32]
        encryptor.iv =  dhHash[32...48]
        EC.base64( fromHex(ptTmp.to_bn(:compressed).to_s(16)) + encryptor.update(msg) + encryptor.final)
    end
  end
end
