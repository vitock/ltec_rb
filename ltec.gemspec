# frozen_string_literal: true

require_relative "lib/ltec/version"

Gem::Specification.new do |spec|
  spec.name = "ltec"
  spec.version = Ltec::VERSION
  spec.authors = ["vitock"]
  spec.email = [""]

  spec.summary = "using ECC to enrypt private message"
  spec.description = "using ECC  to enrypt private message with ruby ,the curve is SECP256k1  "
  spec.homepage = "https://github.com/vitock/ltec_rb.git"
  spec.required_ruby_version = ">= 2.6.0"

  # spec.metadata["allowed_push_host"] = "TODO: Set to your gem server 'https://example.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/vitock/ltec_rb.git"
  spec.metadata["changelog_uri"] = "https://github.com/vitock/ltec_rb/blob/master/README.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  spec.add_dependency "openssl"
  spec.add_dependency "base64", "~> 0.1.0"
  

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
