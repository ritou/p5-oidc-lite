use strict;
use warnings;

use Test::More tests => 5;
use OIDC::Lite::Model::ClientInfo;

my $client_info = OIDC::Lite::Model::ClientInfo->new(
    client_id => q{test_client_id},
    client_secret => q{test_client_secret},
    registration_access_token => q{test_registration_access_token},
    expires_at => 1111111,
    metadata => {
        application_type => "web"
    },
);

is($client_info->client_id, q{test_client_id});
is($client_info->client_secret, q{test_client_secret});
is($client_info->registration_access_token, q{test_registration_access_token});
is($client_info->expires_at, 1111111);
is($client_info->metadata->{application_type}, q{web});
