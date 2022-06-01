# frozen_string_literal: true

require_relative "ltec" 

kp = Ltec::EC.generateKeyPair(ARGV[0])
puts kp 
msg = "hello"
msg2 = "hello world3"

enc1 = Ltec::EC.encrypt(kp['pubkey'],msg)
dec1 = Ltec::EC.decrypt(kp['seckey'],enc1)
puts enc1 
puts dec1



enc2 = Ltec::EC.encrypt(kp['pubkey'],msg2)
dec2 = Ltec::EC.decrypt(kp['seckey'],enc2)
puts enc2
puts dec2