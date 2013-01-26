use strict;
use warnings;

use HTTP::Response;
use HTTP::Status qw(:constants);
use Test::More tests => 29;
use Test::Mock::LWP::Conditional;
use LWP::UserAgent;
use HTTP::Response;

use Try::Tiny;
use OIDC::Lite::Client::Registration;
use OIDC::Lite::Server::Endpoint::Registration;
use OAuth::Lite2::Agent::PSGIMock;
use lib 't/lib';
use TestDataHandler;

my $op_registration_endpoint = qw{http://example.com/registration};

# client metadata
my $config = {
    redirect_uris => q{http://example.com/redirect_uri},
    application_name => q{test_app_name},
};

# success response
my $res = HTTP::Response->new(HTTP_OK,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            q{{"client_id":"s6BhdRkqt3","client_secret":"cf136dc3c1fd9153029bb9c6cc9ecead918bad9887fce6c93f31185e5885805d","registration_access_token": "this.is.a.access.token.value","expires_at":2893276800}});

# stub agent
my $agent = LWP::UserAgent->new;
$agent->stub_request($op_registration_endpoint => $res);

my $client = OIDC::Lite::Client::Registration->new(
    registration_endpoint   => $op_registration_endpoint,
    agent => $agent,
);

# associate success
my $credential = $client->associate(
    metadata => $config,
);

ok($credential);
is($credential->{client_id}, "s6BhdRkqt3");
is($credential->{client_secret}, "cf136dc3c1fd9153029bb9c6cc9ecead918bad9887fce6c93f31185e5885805d");
is($credential->{registration_access_token}, "this.is.a.access.token.value");
is($credential->{expires_at}, 2893276800);

# associate failed
$res = HTTP::Response->new(HTTP_BAD_REQUEST,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            "");
$agent->stub_request($op_registration_endpoint => $res);
$credential = $client->associate(
    metadata => $config,
);

ok(!$credential);
is($client->errstr, q{400 Bad Request});

# update success
$res = HTTP::Response->new(HTTP_OK,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            q{{"client_id":"s6BhdRkqt3"}});
$agent->stub_request($op_registration_endpoint => $res);
$credential = $client->update(
    access_token => q{test_access_token},
    metadata => $config,
);

ok($credential);
is($credential->{client_id}, "s6BhdRkqt3");
ok(!$credential->{client_secret});
ok(!$credential->{registration_access_token});
ok(!$credential->{expires_at});

# update failed
$res = HTTP::Response->new(HTTP_BAD_REQUEST,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            "");
$agent->stub_request($op_registration_endpoint => $res);
$credential = $client->update(
    access_token => q{test_access_token},
    metadata => $config,
);

ok(!$credential);
is($client->errstr, q{400 Bad Request});

# rotate_secret success
$res = HTTP::Response->new(HTTP_OK,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            q{{"client_id":"s6BhdRkqt3","client_secret":"cf136dc3c1fd9153029bb9c6cc9ecead918bad9887fce6c93f31185e5885805d","registration_access_token": "this.is.a.access.token.value","expires_at":2893276800}});
$agent->stub_request($op_registration_endpoint => $res);
$credential = $client->rotate_secret(
    access_token => q{test_access_token},
);

is($credential->{client_id}, "s6BhdRkqt3");

$res = HTTP::Response->new(HTTP_BAD_REQUEST,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            "");
$agent->stub_request($op_registration_endpoint => $res);
$credential = $client->rotate_secret(
    access_token => q{test_access_token},
);

ok(!$credential);
is($client->errstr, q{400 Bad Request});

# test with PSGI Mock
my $app = OIDC::Lite::Server::Endpoint::Registration->new(
    data_handler => "TestDataHandler",
);
$agent = OAuth::Lite2::Agent::PSGIMock->new(app => $app);
$app->support_types(qw(client_register client_update rotate_secret));
$client = OIDC::Lite::Client::Registration->new(
    registration_endpoint  => q{http://localhost/registration},
    agent             => $agent,
);
$config = {
    redirect_uris => q{http://example.org/redirect},
};

# client associate
$res = $client->associate(
    metadata => $config,
);
is($res->client_id, q{test_client_id});
is($res->client_secret, q{test_client_secret});
is($res->registration_access_token, q{test_registration_access_token});
is($res->expires_at, 1234567);

# client_update
$res = $client->update(
    access_token => q{test_access_token},
    metadata => $config,
);
is($res->client_id, q{test_client_id});
ok(!$res->client_secret);
ok(!$res->registration_access_token);
ok(!$res->expires_at);

# rotate_secret
$res = $client->rotate_secret(
    access_token => q{test_access_token},
);
is($res->client_id, q{test_client_id});
is($res->client_secret, q{test_client_secret_rotate});
is($res->registration_access_token, q{test_registration_access_token_rotate});
is($res->expires_at, 1234567);
