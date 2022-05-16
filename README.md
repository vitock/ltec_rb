# Ltec

a tinny tool to encryt your private message via ECC(Secp256k1)


# upate 0.1.2
using AES instead of Salsa20 


## Installation

Install the gem and add to the application's Gemfile by executing:

    $ bundle add ltec

If bundler is not being used to manage dependencies, install the gem by executing:

    $ gem install ltec

## Usage

``` ruby
require 'ltec'
kp = Ltec::EC.generateKeyPair()
privateKeyString = kp['seckey']
publicKeyString = kp['pubkey']

message = "hello ruby"
encMsg = Ltec::EC.encrypt(publicKeyString,msg)
decryptMsg = Ltec::EC.decrypt(privateKeyString,msg)

```

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/ltec.
