require('./LTEC')

kp = LTEC::EC.generateKeyPair()
puts kp['seckey']
puts kp['pubkey']

privateKey = kp['seckey']
publicKey = kp['pubkey']
msg = <<EOF
this is a tiniy encrytion tool .
use the curve SECP256k1 as know as BitCoin curve
:)
EOF

privateKey = 'Pfmw0CoXmv9qVmKZUZqkZIa9pmAZ0t9sATur4g3VTNk='
publicKey = 'A135r7ug2MedtYlKlcgM3+SaUm/GwK9mKu3f9N7PzAgA'


enc = LTEC::EC.encrypt(publicKey,msg)
puts "enc",enc
puts "---------------"
puts LTEC::EC.decrypt(privateKey,enc)
