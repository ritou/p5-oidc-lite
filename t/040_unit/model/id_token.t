use strict;
use warnings;

use Test::More tests => 20;
use OIDC::Lite::Model::IDToken;

my $pkeyfile = "t/lib/private_np.pem";
my $pkey;
open(PRIV,$pkeyfile) || die "$pkeyfile: $!";
read(PRIV,$pkey,-s PRIV);
close(PRIV);

TEST_NEW: {

    my $id_token = OIDC::Lite::Model::IDToken->new();
    
    ok($id_token->header);
    ok($id_token->payload);
    is($id_token->key, undef);

    my %header =    (
                        typ =>'JWT',
                        alg => 'none',
                    );
    my %payload =   (
                        foo => 'bar'
                    );
    my $key = q{this_is_shared_secret_key};
    $id_token = OIDC::Lite::Model::IDToken->new(
        header  => \%header,
        payload => \%payload,
        key     => $key,
    );
    is($id_token->header,   \%header);
    is($id_token->payload,  \%payload);
    is($id_token->key,      $key);

};

TEST_GET_TOKEN_STRING: {

    # alg : none
    my %header =    (
                        alg => 'none',
                        typ => 'JWS',
                    );
    my %payload =   (
                        foo => 'bar'
                    );
    my $id_token = OIDC::Lite::Model::IDToken->new(
        header  => \%header,
        payload => \%payload,
    );
    my $id_token_string = $id_token->get_token_string();
    is( $id_token_string, 'eyJ0eXAiOiJKV1MiLCJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.');

    # alg : HS256
    %header =       (
                        alg => 'HS256',
                        typ => 'JWS',
                    );
    %payload =      (
                        foo => 'bar'
                    );
    my $key = q{this_is_shared_secret_key};
    $id_token = OIDC::Lite::Model::IDToken->new(
        header  => \%header,
        payload => \%payload,
        key     => $key,
    );
    $id_token_string = $id_token->get_token_string();
    is( $id_token_string, 'eyJ0eXAiOiJKV1MiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.Q3cQIgBthdlPPhP5elxuD58iB-Vw2AtxPDPlXng3YaM');

    # alg : RS256
    %header =       (
                        alg => 'RS256',
                        typ => 'JWS',
                    );
    %payload =      (
                        foo => 'bar'
                    );
    $id_token = OIDC::Lite::Model::IDToken->new(
        header  => \%header,
        payload => \%payload,
        key     => $pkey,
    );
    $id_token_string = $id_token->get_token_string();
    is( $id_token_string, 'eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.M3bzN8GKhPxFyENIwcnLb7S_ofOHOjJDh1LXfK5X8No60PGCVa5JIgDeHKLC4_g-mnUqq-JEmxVc8so3FpPWea8c4zHWU1tr1n-GLFO4TSAnsIfuPFcvJB8rNVe4iHA4ePKqUE8Z7jb_d0pcg4NpXr0GYPIg_NQbQIPwjpNz789dpNH3_OClJxeY_ELMkWoZAWHO6uTymPnmlg2KK0PlRp60yWhHi9JlgObYrUEItnjfOyOOqL37oL-S4GyENYFbzcdkCicPIFnnK4oFIY-NmO5Fh6g-NaSPSmgcSiJzbOOdaWNeG6HDQINAEcwT18vUHRVwzGqU1AATztDGpF3mVQ');
};

TEST_LOAD: {
    # alg : none
    my $token_string = '';
    my $id_token = OIDC::Lite::Model::IDToken->load($token_string);
    is( $id_token, undef);

    $token_string = 'eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJmb28iOiJiYXIifQ.';
    $id_token = OIDC::Lite::Model::IDToken->load($token_string);
    ok( $id_token );

    my %header =    (
                        alg => 'none',
                        typ =>'JWS',
                    );
    my %payload =   (
                        foo => 'bar'
                    );
    is( %{$id_token->header}, %header);
    is( %{$id_token->payload}, %payload);
};

TEST_VERIFY: {

    # alg : none
    my $token_string = 'eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJmb28iOiJiYXIifQ.';
    my $id_token = OIDC::Lite::Model::IDToken->load($token_string);
    ok($id_token->verify());

    $token_string = 'eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJmb28iOiJiYXIifQ.INVALID';
    $id_token = OIDC::Lite::Model::IDToken->load($token_string);
    ok(!$id_token->verify());

    # alg : HS256
    $token_string = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.Q3cQIgBthdlPPhP5elxuD58iB-Vw2AtxPDPlXng3YaM';
    $id_token = OIDC::Lite::Model::IDToken->load($token_string);
    my $key = q{this_is_shared_secret_key};
    $id_token->key($key);
    ok($id_token->verify());

    $token_string = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.Q3cQIgBthdlPPhP5elxuD58iB-Vw2AtxPDPlXng3YaM';
    $id_token = OIDC::Lite::Model::IDToken->load($token_string);
    $key = q{this_is_invalid_shared_secret_key};
    $id_token->key($key);
    ok(!$id_token->verify());

    $token_string = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.INVALIDSIGNATURE';
    $id_token = OIDC::Lite::Model::IDToken->load($token_string);
    $key = q{this_is_shared_secret_key};
    $id_token->key($key);
    ok(!$id_token->verify());

    # alg : RS256
    $token_string = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.M3bzN8GKhPxFyENIwcnLb7S_ofOHOjJDh1LXfK5X8No60PGCVa5JIgDeHKLC4_g-mnUqq-JEmxVc8so3FpPWea8c4zHWU1tr1n-GLFO4TSAnsIfuPFcvJB8rNVe4iHA4ePKqUE8Z7jb_d0pcg4NpXr0GYPIg_NQbQIPwjpNz789dpNH3_OClJxeY_ELMkWoZAWHO6uTymPnmlg2KK0PlRp60yWhHi9JlgObYrUEItnjfOyOOqL37oL-S4GyENYFbzcdkCicPIFnnK4oFIY-NmO5Fh6g-NaSPSmgcSiJzbOOdaWNeG6HDQINAEcwT18vUHRVwzGqU1AATztDGpF3mVQ';
    $id_token = OIDC::Lite::Model::IDToken->load($token_string);
    $id_token->key($pkey);
    ok($id_token->verify());

    $token_string = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.INVALID';
    $id_token = OIDC::Lite::Model::IDToken->load($token_string);
    $id_token->key($pkey);
    ok(!$id_token->verify());
};
