use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 83;

use Plack::Request;
use Try::Tiny;
use TestDataHandler;
use OIDC::Lite::Server::AuthorizationHandler;
use OAuth::Lite2::Util qw(build_content);
use OAuth::Lite2::Server::Error;

TestDataHandler->clear;
TestDataHandler->add_client(    id => q{client_id_1}, 
                                response_type => q{code}, 
                                redirect_uri => q{http://rp.example.org/redirect}, 
                                scope => q{openid}, 
);

TestDataHandler->add_client(    id => q{client_id_2}, 
                                response_type => q{id_token token}, 
                                redirect_uri => q{http://rp.example.org/redirect}, 
                                scope => q{openid}, 
);

TEST_RESPONSE_TYPE: {
    # not found
    my $params = {
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my @allowed_response_type = qw(code token);
    my $dh = TestDataHandler->new(request => $request);
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    ok($authz_handler);

    my $error_message;
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_request: 'response_type' not found});

    # not allowed
    $params = {
                response_type => q{id_token},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    undef($error_message);
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_request: 'response_type' not allowed});
};

TEST_CLIENT_ID: {
    # no client_id
    my $params = {
                response_type => q{token},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my @allowed_response_type = qw(code token);
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    my $error_message;
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_client: 'client_id' not found});

    # invalid
    $params = {
                response_type => q{token},
                client_id     => q{malformed},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    @allowed_response_type = qw(code token);
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    undef($error_message);
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_client: });

    # not allowed(client_id, response_type)
    $params = {
                response_type => q{token},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    @allowed_response_type = qw(code token);
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    undef($error_message);
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_request: 'response_type' not allowed for this 'client_id'});
};

TEST_REDIRECT_URI: {
    # not found
    my $params = {
                response_type => q{code},
                client_id     => q{client_id_1},
                scope         => q{openid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my @allowed_response_type = qw(code token);
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    my $error_message;
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_request: 'redirect_uri' not found});

    # invalid
    $params = {
                response_type => q{code},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/invalid},
                scope         => q{openid},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    @allowed_response_type = qw(code token);
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    undef($error_message);
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_request: 'redirect_uri' is invalid});
};

TEST_SCOPE: {
    # invalid
    my $params = {
                response_type => q{code},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{invalid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my @allowed_response_type = qw(code token);
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    my $error_message;
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_scope: });
};

TEST_NONCE: {
    # required
    my $params = {
                response_type => q{token id_token},
                client_id     => q{client_id_2},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my @allowed_response_type = ("code", "token", "id_token token");
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    my $error_message;
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_request: nonce_required});
};

TEST_DISPLAY: {

    # invalid
    my $params = {
                response_type => q{code},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
                display       => q{invalid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my @allowed_response_type = ("code", "token", "id_token token");
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    my $error_message;
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_request: 'display' is invalid});

};

TEST_PROMPT: {

    # invalid
    my $params = {
                response_type => q{code},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
                prompt        => q{invalid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my @allowed_response_type = ("code", "token", "id_token token");
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    my $error_message;
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_request: 'prompt' is invalid});

};

TEST_REQUEST: {

    # invalid
    my $params = {
                response_type => q{code},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
                request       => q{invalid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my @allowed_response_type = ("code", "token", "id_token token");
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    my $error_message;
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_request: 'request' is invalid});

};

TEST_REQUEST_URI: {

    # invalid
    my $params = {
                response_type => q{code},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
                request_uri   => q{invalid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my @allowed_response_type = ("code", "token", "id_token token");
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    my $error_message;
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_request: 'request_uri' is invalid});

};

TEST_REQUEST_ID_TOKEN: {

    # invalid
    my $params = {
                response_type => q{code},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
                id_token      => q{invalid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my @allowed_response_type = ("code", "token", "id_token token");
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    my $error_message;
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    is($error_message, q{invalid_request: 'id_token' is invalid});

};

TEST_REQUEST_SUCCESS: {
    # no error
    my $params = {
                response_type => q{code},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my @allowed_response_type = ("code", "token", "id_token token");
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    my $error_message;
    try {
        $authz_handler->handle_request();
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };
    ok(!$error_message);
};

TEST_REQUEST_DENY: {
    # code, no state
    my $params = {
                response_type => q{code},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my @allowed_response_type = ("code", "token", "id_token token");
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    my $res = $authz_handler->deny();
    is($res->{redirect_uri}, $params->{redirect_uri});
    is($res->{query}->{error}, q{access_denied});
    ok(!$res->{query}->{state});

    # code, state
    $params = {
                response_type => q{code},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
                state         => q{state_str},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    @allowed_response_type = ("code", "token", "id_token token");
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    $res = $authz_handler->deny();
    is($res->{redirect_uri}, $params->{redirect_uri});
    is($res->{query}->{error}, q{access_denied});
    is($res->{query}->{state}, $params->{state});

    # token, no state
    $params = {
                response_type => q{token},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    @allowed_response_type = ("code", "token", "id_token token");
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    $res = $authz_handler->deny();
    is($res->{redirect_uri}, $params->{redirect_uri});
    is($res->{fragment}->{error}, q{access_denied});
    ok(!$res->{fragment}->{state});

    # token, state
    $params = {
                response_type => q{token},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
                state         => q{state_str},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    @allowed_response_type = ("code", "token", "id_token token");
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    $res = $authz_handler->deny();
    is($res->{redirect_uri}, $params->{redirect_uri});
    is($res->{fragment}->{error}, q{access_denied});
    is($res->{fragment}->{state}, $params->{state});
};


TEST_REQUEST_ALLOW: {
    # code
    my $params = {
                response_type => q{code},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my @allowed_response_type = ("code");
    my $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    my $res = $authz_handler->allow();
    is($res->{redirect_uri}, $params->{redirect_uri});
    ok(!$res->{query}->{error});
    is($res->{query}->{code}, q{code_0});
    ok(!$res->{fragment});

    # token
    $params = {
                response_type => q{token},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    @allowed_response_type = ("token");
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    $res = $authz_handler->allow();
    is($res->{redirect_uri}, $params->{redirect_uri});
    ok(!$res->{fragment}->{error});
    ok(!$res->{fragment}->{code});
    ok(!$res->{fragment}->{id_token});
    is($res->{fragment}->{access_token}, q{access_token_0});
    is($res->{fragment}->{token_type}, q{Bearer});
    ok($res->{fragment}->{expires_in});
    ok(!$res->{query});

    # id_token
    $params = {
                response_type => q{id_token},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    @allowed_response_type = ("id_token");
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    $res = $authz_handler->allow();
    is($res->{redirect_uri}, $params->{redirect_uri});
    ok(!$res->{fragment}->{error});
    ok(!$res->{fragment}->{code});
    ok($res->{fragment}->{id_token});
    is($res->{fragment}->{id_token}, q{eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjEzNDkyNTc3OTcsImlhdCI6MTM0OTI1NzE5NywiYXVkIjoiYXVkc3RyIiwidXNlcl9pZCI6IjEiLCJpc3MiOiJpc3NzdHIifQ.5N_PG_KTTFFYnwJK6Y_ljNMM5_L9ZyiDqDLEqt-nR1M});
    ok(!$res->{fragment}->{access_token});
    ok(!$res->{fragment}->{token_type});
    ok(!$res->{fragment}->{expires_in});
    ok(!$res->{query});

    # code id_token
    $params = {
                response_type => q{code id_token},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    @allowed_response_type = ("code id_token");
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    $res = $authz_handler->allow();
    is($res->{redirect_uri}, $params->{redirect_uri});
    ok(!$res->{fragment}->{error});
    is($res->{fragment}->{code}, q{code_3});
    ok($res->{fragment}->{id_token});
    is($res->{fragment}->{id_token}, q{eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjEzNDkyNTc3OTcsImlhdCI6MTM0OTI1NzE5NywiYXVkIjoiYXVkc3RyIiwidXNlcl9pZCI6IjEiLCJpc3MiOiJpc3NzdHIiLCJjX2hhc2giOiJ2NDR2aEJSWUU5Nk16ZkxNek5kcGhnIn0.Q-IkEr82dJik_scGTvY83WRc7aCm_1shVG5Bsv8ST0k});
    ok(!$res->{fragment}->{access_token});
    ok(!$res->{fragment}->{token_type});
    ok(!$res->{fragment}->{expires_in});
    ok(!$res->{query});

    # code token
    $params = {
                response_type => q{code token},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    @allowed_response_type = ("code token");
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    $res = $authz_handler->allow();
    is($res->{redirect_uri}, $params->{redirect_uri});
    ok(!$res->{fragment}->{error});
    is($res->{fragment}->{code}, q{code_4});
    ok(!$res->{fragment}->{id_token});
    is($res->{fragment}->{access_token}, q{access_token_1});
    is($res->{fragment}->{token_type}, q{Bearer});
    ok($res->{fragment}->{expires_in});
    ok(!$res->{query});

    # id_token token
    $params = {
                response_type => q{id_token token},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    @allowed_response_type = ("id_token token");
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    $res = $authz_handler->allow();
    is($res->{redirect_uri}, $params->{redirect_uri});
    ok(!$res->{fragment}->{error});
    ok(!$res->{fragment}->{code});
    ok($res->{fragment}->{id_token});
    is($res->{fragment}->{id_token}, q{eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjEzNDkyNTc3OTcsImlhdCI6MTM0OTI1NzE5NywiYXRfaGFzaCI6IlJpalczZHJmd2dBZ0tsYWYxLWwwSmciLCJhdWQiOiJhdWRzdHIiLCJ1c2VyX2lkIjoiMSIsImlzcyI6Imlzc3N0ciJ9.QBG9Ix09JY6jS2UpSM3B5vsYx7sReL5T5n9S4uPiF6o});
    is($res->{fragment}->{access_token}, q{access_token_2});
    is($res->{fragment}->{token_type}, q{Bearer});
    ok($res->{fragment}->{expires_in});
    ok(!$res->{query});

    # code id_token token
    $params = {
                response_type => q{code id_token token},
                client_id     => q{client_id_1},
                redirect_uri  => q{http://rp.example.org/redirect},
                scope         => q{openid},
    };

    $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    $dh = TestDataHandler->new(request => $request);
    @allowed_response_type = ("code id_token token");
    $authz_handler = OIDC::Lite::Server::AuthorizationHandler->new(data_handler => $dh, response_types => \@allowed_response_type);
    $res = $authz_handler->allow();
    is($res->{redirect_uri}, $params->{redirect_uri});
    ok(!$res->{fragment}->{error});
    is($res->{fragment}->{code}, q{code_6});
    ok($res->{fragment}->{id_token});
    is($res->{fragment}->{access_token}, q{access_token_3});
    is($res->{fragment}->{token_type}, q{Bearer});
    ok($res->{fragment}->{expires_in});
    ok(!$res->{query});

}
