use strict;
use warnings;

use Test::More tests => 56;
use Try::Tiny;
use OIDC::Lite::Server::Error;

TEST_INVALID_OPERATION: {
    my $error = OIDC::Lite::Server::Error::InvalidOperation->new;
    ok($error->isa("OIDC::Lite::Server::Error"));
    is($error->type, "invalid_operation");
    is($error->code, 400);
    ok(!$error->state);
    ok(!$error->description);

    try {
        OIDC::Lite::Server::Error::InvalidOperation->throw;
    } catch {
        ok($_->isa("OIDC::Lite::Server::Error"));
        ok($_->isa("OAuth::Lite2::Server::Error"));
        is($_, $error);
    };

    $error = OIDC::Lite::Server::Error::InvalidOperation->new(
        description => q{The value of type is invalid or not supported}
    );
    ok($error->isa("OIDC::Lite::Server::Error"));
    is($error->type, "invalid_operation");
    is($error->code, 400);
    is($error->description, q{The value of type is invalid or not supported});
    ok(!$error->state);

    try {
        OIDC::Lite::Server::Error::InvalidOperation->throw(
            description => q{The value of type is invalid or not supported}
        );
    } catch {
        ok($_->isa("OIDC::Lite::Server::Error"));
        ok($_->isa("OAuth::Lite2::Server::Error"));
        is($_, $error);
    };
};

TEST_INVALID_CLIENT_ID: {
    my $error = OIDC::Lite::Server::Error::InvalidClientId->new;
    ok($error->isa("OIDC::Lite::Server::Error"));
    is($error->type, "invalid_client_id");
    is($error->code, 400);
    ok(!$error->state);
    ok(!$error->description);

    try {
        OIDC::Lite::Server::Error::InvalidClientId->throw;
    } catch {
        ok($_->isa("OIDC::Lite::Server::Error"));
        ok($_->isa("OAuth::Lite2::Server::Error"));
        is($_, $error);
    };
};

TEST_INVALID_CLIENT_SECRET: {
    my $error = OIDC::Lite::Server::Error::InvalidClientSecret->new;
    ok($error->isa("OIDC::Lite::Server::Error"));
    is($error->type, "invalid_client_secret");
    is($error->code, 400);
    ok(!$error->state);
    ok(!$error->description);

    try {
        OIDC::Lite::Server::Error::InvalidClientSecret->throw;
    } catch {
        ok($_->isa("OIDC::Lite::Server::Error"));
        ok($_->isa("OAuth::Lite2::Server::Error"));
        is($_, $error);
    };
};

TEST_INVALID_CLIENT_ID: {
    my $error = OIDC::Lite::Server::Error::InvalidClientId->new;
    ok($error->isa("OIDC::Lite::Server::Error"));
    is($error->type, "invalid_client_id");
    is($error->code, 400);
    ok(!$error->state);
    ok(!$error->description);

    try {
        OIDC::Lite::Server::Error::InvalidClientId->throw;
    } catch {
        ok($_->isa("OIDC::Lite::Server::Error"));
        ok($_->isa("OAuth::Lite2::Server::Error"));
        is($_, $error);
    };
};

TEST_INVALID_REDIRECT_URI: {
    my $error = OIDC::Lite::Server::Error::InvalidRedirectUri->new;
    ok($error->isa("OIDC::Lite::Server::Error"));
    is($error->type, "invalid_redirect_uri");
    is($error->code, 400);
    ok(!$error->state);
    ok(!$error->description);

    try {
        OIDC::Lite::Server::Error::InvalidRedirectUri->throw;
    } catch {
        ok($_->isa("OIDC::Lite::Server::Error"));
        ok($_->isa("OAuth::Lite2::Server::Error"));
        is($_, $error);
    };
};

TEST_INVALID_CONFIGURATION_PARAMETER: {
    my $error = OIDC::Lite::Server::Error::InvalidConfigurationParameter->new;
    ok($error->isa("OIDC::Lite::Server::Error"));
    is($error->type, "invalid_configuration_parameter");
    is($error->code, 400);
    ok(!$error->state);
    ok(!$error->description);

    try {
        OIDC::Lite::Server::Error::InvalidConfigurationParameter->throw;
    } catch {
        ok($_->isa("OIDC::Lite::Server::Error"));
        ok($_->isa("OAuth::Lite2::Server::Error"));
        is($_, $error);
    };
};
