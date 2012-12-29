use strict;
use warnings;

use Test::More tests => 4;
use OIDC::Lite::Client::Credential;

my $result = {
    client_id => q{test_client_id},
    client_secret => q{test_client_secret},
    registration_access_token => q{test_registration_access_token},
    expires_at => 1111111,
};
my $credential = OIDC::Lite::Client::Credential->new($result);

is($credential->client_id, q{test_client_id});
is($credential->client_secret, q{test_client_secret});
is($credential->registration_access_token, q{test_registration_access_token});
is($credential->expires_at, 1111111);
