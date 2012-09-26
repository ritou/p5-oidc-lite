use strict;
use warnings;

use Test::More tests => 12;
use OIDC::Lite::Model::AuthInfo;

TEST_NEW: {

    my $token = OIDC::Lite::Model::AuthInfo->new(
        id          => q{test_id},
        user_id     => q{test_user_id},
        client_id   => q{test_client_id},
    );

    is($token->id,          q{test_id});
    is($token->user_id,     q{test_user_id});
    is($token->client_id,   q{test_client_id});

    undef($token);
    my @claims = (q{foo}, q{bar});
    $token = OIDC::Lite::Model::AuthInfo->new(
        id              => q{test_id},
        user_id         => q{test_user_id},
        client_id       => q{test_client_id},
        scope           => q{test_scope},
        refresh_token   => q{test_refresh_token},
        code            => q{test_code},
        redirect_uri    => q{test_redirect_uri},
        id_token        => q{test_id_token},
        userinfo_claims => \@claims,
    );

    is($token->id,              q{test_id});
    is($token->user_id,         q{test_user_id});
    is($token->client_id,       q{test_client_id});
    is($token->scope,           q{test_scope});
    is($token->refresh_token,   q{test_refresh_token});
    is($token->code,            q{test_code});
    is($token->redirect_uri,    q{test_redirect_uri});
    is($token->id_token,        q{test_id_token});
    is($token->userinfo_claims, \@claims);

};
