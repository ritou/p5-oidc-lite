use strict;
use warnings;

use Test::More tests => 6;
use JSON::WebToken;
use OIDC::Lite::Util::JWT;
use JSON qw/decode_json encode_json/;

TEST_HEADER: {
    my %header =    (
                        typ => 'JWS',
                        alg => 'HS256',
                    );
    my %payload =   (
                        foo => 'bar'
                    );
    my $key = '';
    my $jwt = JSON::WebToken->encode(\%payload, $key, $header{alg}, \%header);
    is(encode_json(OIDC::Lite::Util::JWT::header($jwt)), encode_json(\%header));
    is(encode_json(OIDC::Lite::Util::JWT::header('invalid_jwt')), encode_json({}));
    is(encode_json(OIDC::Lite::Util::JWT::header('invalid_header.invalid_payload.')), encode_json({}));
};

TEST_PAYLOAD: {
    my %header =    (
                        typ => 'JWS',
                        alg => 'HS256',
                    );
    my %payload =   (
                        foo => 'bar'
                    );
    my $key = '';
    my $jwt = JSON::WebToken->encode(\%payload, $key, $header{alg}, \%header);
    is(encode_json(OIDC::Lite::Util::JWT::payload($jwt)), encode_json(\%payload));
    is(encode_json(OIDC::Lite::Util::JWT::payload('invalid_jwt')), encode_json({}));
    is(encode_json(OIDC::Lite::Util::JWT::payload('invalid_header.invalid_payload.')), encode_json({}));
};
