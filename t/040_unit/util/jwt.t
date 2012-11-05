use strict;
use warnings;

use Test::More tests => 13;
use OIDC::Lite::Util::JWT;
use JSON qw/decode_json encode_json/;

my $pkeyfile = "t/lib/private_np.pem";
my $pkey;
open(PRIV,$pkeyfile) || die "$pkeyfile: $!";
read(PRIV,$pkey,-s PRIV);
close(PRIV);

TEST_ENCODE: {
    # none
    my %header =    (
                        alg => 'none',
                        typ => 'JWS',
                    );
    my %payload =   (
                        foo => 'bar'
                    );
    my $key = '';
    my $jwt = OIDC::Lite::Util::JWT->encode(\%header, \%payload, $key);
    is( $jwt, 'eyJ0eXAiOiJKV1MiLCJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.');

    # HS256
    %header =    (
                        alg => 'HS256',
                        typ => 'JWS',
                    );
    %payload =   (
                        foo => 'bar'
                    );
    $key = q{this_is_shared_secret_key};
    $jwt = OIDC::Lite::Util::JWT->encode(\%header, \%payload, $key);
    is( $jwt, 'eyJ0eXAiOiJKV1MiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.Q3cQIgBthdlPPhP5elxuD58iB-Vw2AtxPDPlXng3YaM');

    # RS256
    %header =    (
                        alg => 'RS256',
                        typ => 'JWS',
                    );
    %payload =   (
                        foo => 'bar'
                    );
    $jwt = OIDC::Lite::Util::JWT->encode(\%header, \%payload, $pkey);
    is( $jwt, 'eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.M3bzN8GKhPxFyENIwcnLb7S_ofOHOjJDh1LXfK5X8No60PGCVa5JIgDeHKLC4_g-mnUqq-JEmxVc8so3FpPWea8c4zHWU1tr1n-GLFO4TSAnsIfuPFcvJB8rNVe4iHA4ePKqUE8Z7jb_d0pcg4NpXr0GYPIg_NQbQIPwjpNz789dpNH3_OClJxeY_ELMkWoZAWHO6uTymPnmlg2KK0PlRp60yWhHi9JlgObYrUEItnjfOyOOqL37oL-S4GyENYFbzcdkCicPIFnnK4oFIY-NmO5Fh6g-NaSPSmgcSiJzbOOdaWNeG6HDQINAEcwT18vUHRVwzGqU1AATztDGpF3mVQ');
};

TEST_VERIFY: {
    # none
    my %header =    (
                        alg => 'none',
                        typ => 'JWS',
                    );
    my %payload =   (
                        foo => 'bar'
                    );
    my $key = '';
    my $jwt = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.';
    ok(OIDC::Lite::Util::JWT->verify($jwt, $key));
    $jwt = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.INVALID';
    ok(!OIDC::Lite::Util::JWT->verify($jwt, $key));

    # HS256
    %header =    (
                        alg => 'HS256',
                        typ => 'JWS',
                    );
    %payload =   (
                        foo => 'bar'
                    );
    $key = q{this_is_shared_secret_key};
    $jwt = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.Q3cQIgBthdlPPhP5elxuD58iB-Vw2AtxPDPlXng3YaM';
    ok(OIDC::Lite::Util::JWT->verify($jwt, $key));
    $jwt = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.INVALID';
    ok(!OIDC::Lite::Util::JWT->verify($jwt, $key));

    # RS256
    %header =    (
                        alg => 'RS256',
                        typ => 'JWS',
                    );
    %payload =   (
                        foo => 'bar'
                    );
    $jwt = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.M3bzN8GKhPxFyENIwcnLb7S_ofOHOjJDh1LXfK5X8No60PGCVa5JIgDeHKLC4_g-mnUqq-JEmxVc8so3FpPWea8c4zHWU1tr1n-GLFO4TSAnsIfuPFcvJB8rNVe4iHA4ePKqUE8Z7jb_d0pcg4NpXr0GYPIg_NQbQIPwjpNz789dpNH3_OClJxeY_ELMkWoZAWHO6uTymPnmlg2KK0PlRp60yWhHi9JlgObYrUEItnjfOyOOqL37oL-S4GyENYFbzcdkCicPIFnnK4oFIY-NmO5Fh6g-NaSPSmgcSiJzbOOdaWNeG6HDQINAEcwT18vUHRVwzGqU1AATztDGpF3mVQ';
    ok(OIDC::Lite::Util::JWT->verify($jwt, $pkey));
    $jwt = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.INVALID';
    ok(!OIDC::Lite::Util::JWT->verify($jwt, $pkey));
};

TEST_HEADER: {
    my %header =    (
                        typ => 'JWS',
                    );
    my %payload =   (
                        foo => 'bar'
                    );
    my $key = '';
    my $jwt = OIDC::Lite::Util::JWT->encode(\%header, \%payload, $key);
    is(encode_json(OIDC::Lite::Util::JWT->header($jwt)), encode_json(\%header));
    is(encode_json(OIDC::Lite::Util::JWT->header('invalid_jwt')), encode_json({}));
};

TEST_PAYLOAD: {
    my %header =    (
                        typ => 'JWS',
                    );
    my %payload =   (
                        foo => 'bar'
                    );
    my $key = '';
    my $jwt = OIDC::Lite::Util::JWT->encode(\%header, \%payload, $key);
    is(encode_json(OIDC::Lite::Util::JWT->payload($jwt)), encode_json(\%payload));
    is(encode_json(OIDC::Lite::Util::JWT->payload('invalid_jwt')), encode_json({}));
};
