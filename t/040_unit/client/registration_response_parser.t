use strict;
use warnings;

use HTTP::Response;
use HTTP::Status qw(:constants);
use Test::More tests => 23;
use Try::Tiny;
use OIDC::Lite::Client::RegistrationResponseParser;

# success response
my $res = HTTP::Response->new(HTTP_OK,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            q{{"client_id":"s6BhdRkqt3","client_secret":"cf136dc3c1fd9153029bb9c6cc9ecead918bad9887fce6c93f31185e5885805d","registration_access_token": "this.is.a.access.token.value","expires_at":2893276800}});

my $parser = OIDC::Lite::Client::RegistrationResponseParser->new;
my $credential;
my $errmsg;
try {
    $credential = $parser->parse($res, 1);
} catch {
    $errmsg = "$_";
};
ok(!$errmsg);
is($credential->{client_id}, "s6BhdRkqt3");
is($credential->{client_secret}, "cf136dc3c1fd9153029bb9c6cc9ecead918bad9887fce6c93f31185e5885805d");
is($credential->{registration_access_token}, "this.is.a.access.token.value");
is($credential->{expires_at}, 2893276800);

# failed response
$res = HTTP::Response->new(HTTP_BAD_REQUEST,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            "");

try {
    $credential = $parser->parse($res, 1);
} catch {
    $errmsg = "$_";
};
is($errmsg, q{400 Bad Request});

# failed response with msg
$res = HTTP::Response->new(HTTP_BAD_REQUEST,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            q{{"error_code":"invalid_operation","error_description":"The value of the operation parameter must be one of client_register, rotate_secret or client_update."}});

try {
    $credential = $parser->parse($res, 1);
} catch {
    $errmsg = "$_";
};
is($errmsg, q{{"error_code":"invalid_operation","error_description":"The value of the operation parameter must be one of client_register, rotate_secret or client_update."}});

# invalid content_type
$res = HTTP::Response->new(HTTP_OK,
            "",
            [ "Content-Type"  => q{application/jsan},
              "Cache-Control" => "no-store"  ],
            q{{"client_id":"s6BhdRkqt3","client_secret":"cf136dc3c1fd9153029bb9c6cc9ecead918bad9887fce6c93f31185e5885805d","registration_access_token": "this.is.a.access.token.value","expires_at":2893276800}});
try {
    $credential = $parser->parse($res, 1);
} catch {
    $errmsg = "$_";
};
is($errmsg, q{Invalid response content-type: application/jsan});

# invalid response format
$res = HTTP::Response->new(HTTP_OK,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            q{format is invalid});
try {
    $credential = $parser->parse($res, 1);
} catch {
    $errmsg = "$_";
};
ok($errmsg);

# no client_id
$res = HTTP::Response->new(HTTP_OK,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            q{{"client_secret":"cf136dc3c1fd9153029bb9c6cc9ecead918bad9887fce6c93f31185e5885805d","registration_access_token": "this.is.a.access.token.value","expires_at":2893276800}});
try {
    $credential = $parser->parse($res, 1);
} catch {
    $errmsg = "$_";
};
is($errmsg, q{Response doesn't include 'client_id'});

# no registration access token
$res = HTTP::Response->new(HTTP_OK,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            q{{"client_id":"s6BhdRkqt3","client_secret":"cf136dc3c1fd9153029bb9c6cc9ecead918bad9887fce6c93f31185e5885805d","expires_at":2893276800}});
try {
    $credential = $parser->parse($res, 1);
} catch {
    $errmsg = "$_";
};
is($errmsg, q{Response doesn't include 'registration_access_token'});

# ok registration access token is empty
$res = HTTP::Response->new(HTTP_OK,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            q{{"client_id":"s6BhdRkqt3","client_secret":"cf136dc3c1fd9153029bb9c6cc9ecead918bad9887fce6c93f31185e5885805d","expires_at":2893276800}});
try {
    $credential = $parser->parse($res);
} catch {
    $errmsg = "$_";
};
is($credential->{client_id}, "s6BhdRkqt3");
is($credential->{client_secret}, "cf136dc3c1fd9153029bb9c6cc9ecead918bad9887fce6c93f31185e5885805d");
ok(!$credential->{registration_access_token});
is($credential->{expires_at}, 2893276800);

# ok registration client_secret is empty
$res = HTTP::Response->new(HTTP_OK,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            q{{"client_id":"s6BhdRkqt3","expires_at":2893276800}});
try {
    $credential = $parser->parse($res);
} catch {
    $errmsg = "$_";
};
is($credential->{client_id}, "s6BhdRkqt3");
ok(!$credential->{client_secret});
ok(!$credential->{registration_access_token});
is($credential->{expires_at}, 2893276800);

# ok registration expires_at is empty
$res = HTTP::Response->new(HTTP_OK,
            "",
            [ "Content-Type"  => q{application/json},
              "Cache-Control" => "no-store"  ],
            q{{"client_id":"s6BhdRkqt3"}});
try {
    $credential = $parser->parse($res);
} catch {
    $errmsg = "$_";
};
is($credential->{client_id}, "s6BhdRkqt3");
ok(!$credential->{client_secret});
ok(!$credential->{registration_access_token});
ok(!$credential->{expires_at});
