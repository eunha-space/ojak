# Remakes mastodon.json: each `unsigned` document signed, and canonicalised,
# by Mastodon's own code path, so that ojak is held to what Mastodon makes.
#
# That path is the json-ld, json-ld-preloaded and rdf-normalize gems at the
# versions Mastodon 4.7.1 locks (3.3.2, 3.3.2, 0.7.0, with rdf 3.3.4), the
# preloaded contexts in Mastodon's config/initializers/json_ld_*.rb, and the
# logic of `ActivityPub::LinkedDataSignature#sign!` and `#verify_actor!`. No
# context is fetched: a document naming one Mastodon would fetch fails.
#
#     gem install json-ld:3.3.2 json-ld-preloaded:3.3.2 rdf:3.3.4 \
#       rdf-normalize:0.7.0
#     MASTODON=path/to/mastodon ruby make.rb > mastodon.json.new
require 'json/ld'
require 'json/ld/preloaded'
require 'rdf/normalize'
require 'openssl'
require 'base64'

%w(json_ld_security json_ld_identity json_ld_cid json_ld_webfinger).each do |f|
  load File.join(ENV.fetch('MASTODON'), 'config/initializers', "#{f}.rb")
end

LOADER = lambda do |url, _opts = {}, &_blk|
  raise JSON::LD::JsonLdError::LoadingDocumentFailed, "not preloaded: #{url}"
end
CONTEXT = 'https://w3id.org/identity/v1'

def canonicalize(json)
  graph = RDF::Graph.new << JSON::LD::API.toRdf(json, documentLoader: LOADER)
  graph.dump(:normalize)
end

def ld_hash(obj) = Digest::SHA256.hexdigest(canonicalize(obj))
def without(hash, *keys) = hash.reject { |k, _| keys.include?(k) }

def sign(json, key_id, keypair, created, expires)
  options = { 'type' => 'RsaSignature2017', 'creator' => key_id, 'created' => created, 'expires' => expires }
  to_be_signed = ld_hash(without(options, 'type', 'id', 'signatureValue').merge('@context' => CONTEXT)) +
                 ld_hash(without(json, 'signature'))
  signature = Base64.strict_encode64(keypair.sign(OpenSSL::Digest.new('SHA256'), to_be_signed))
  context = Array(json['@context'])
  context << 'https://w3id.org/security/v1'
  context.uniq!
  context = context.first if context.size == 1
  json.merge('signature' => options.merge('signatureValue' => signature), '@context' => context)
end

def verify(json, public_key)
  opts = JSON::LD::API.compact(json['signature'].merge('@context' => CONTEXT), CONTEXT, documentLoader: LOADER)
  to_be_verified = ld_hash(without(opts, 'type', 'id', 'signatureValue')) + ld_hash(without(json, 'signature'))
  public_key.verify(OpenSSL::Digest.new('SHA256'), Base64.decode64(opts['signatureValue']), to_be_verified)
end

dir = __dir__
key = OpenSSL::PKey::RSA.new(File.read(File.join(dir, 'key.pem')))
previous = JSON.parse(File.read(File.join(dir, 'mastodon.json'), encoding: 'UTF-8'))
created = '2026-10-01T12:00:00Z'
expires = '2026-10-03T12:00:00Z'
key_id = 'https://m.example/users/alice#main-key'
vectors = previous['vectors'].map do |vector|
  doc = vector['unsigned']
  signed = sign(doc, key_id, key, created, expires)
  raise "does not verify: #{vector['name']}" unless verify(JSON.parse(signed.to_json), key.public_key)

  { 'name' => vector['name'], 'unsigned' => doc, 'signed' => signed, 'canonical' => canonicalize(doc) }
end
puts JSON.pretty_generate('key_id' => key_id, 'created' => created, 'expires' => expires,
                          'public_key_pem' => key.public_key.to_pem, 'vectors' => vectors)
