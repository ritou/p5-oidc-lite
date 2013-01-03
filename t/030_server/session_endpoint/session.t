use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 24;

use Plack::Request;
use Try::Tiny;
use TestDataHandler;
use OIDC::Lite::Server::SessionHandler;
use OAuth::Lite2::Util qw(build_content);

TestDataHandler->clear;

my $privkeyfile = "t/lib/private_np.pem";
my $privkey;
open(PRIV,$privkeyfile) || die "$privkeyfile: $!";
read(PRIV,$privkey,-s PRIV);
close(PRIV);

TEST_NO_ID_TOKEN: {
    my $params = {
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my $session_handler = OIDC::Lite::Server::SessionHandler->new(data_handler => $dh);
    ok($session_handler);

    my $res = $session_handler->handle_request();
    ok($res);
    ok(!$res->{is_valid});
    ok(!$res->{client_id});
    ok(!$res->{javascript_origin_uris});
    ok(!$res->{ops});
};

TEST_CLIENT_ID: {

    my %header =    (
                        typ =>'JWT',
                        alg => 'none',
                    );
    my %payload =   (
                        aud => 'malformed'
                    );
    my $key = q{this_is_shared_secret_key};
    my $id_token = OIDC::Lite::Model::IDToken->new(
        header  => \%header,
        payload => \%payload,
        key     => $key,
    );

    my $params = {
        id_token_hint => $id_token->get_token_string(),
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my $session_handler = OIDC::Lite::Server::SessionHandler->new(data_handler => $dh);
    ok($session_handler);

    my $res = $session_handler->handle_request();
    ok($res);
    ok(!$res->{is_valid});
    is($res->{client_id}, 'malformed');
    ok(!$res->{javascript_origin_uris});
    ok(!$res->{ops});
};

TEST_ORIGIN_URIS: {

    my %header =    (
                        typ =>'JWT',
                        alg => 'none',
                    );
    my %payload =   (
                        aud => 'test_client_id_no_origin_uris'
                    );
    my $key = q{this_is_shared_secret_key};
    my $id_token = OIDC::Lite::Model::IDToken->new(
        header  => \%header,
        payload => \%payload,
        key     => $key,
    );

    my $params = {
        id_token_hint => $id_token->get_token_string(),
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my $session_handler = OIDC::Lite::Server::SessionHandler->new(data_handler => $dh);
    ok($session_handler);

    my $res = $session_handler->handle_request();
    ok($res);
    ok(!$res->{is_valid});
    is($res->{client_id}, 'test_client_id_no_origin_uris');
    is($res->{javascript_origin_uris}->[0], 'http://example.com');
    ok(!$res->{ops});
};

TEST_OPS: {

    my %header =    (
                        typ =>'JWT',
                        alg => 'none',
                    );
    my %payload =   (
                        aud => 'test_client_id'
                    );
    my $key = q{this_is_shared_secret_key};
    my $id_token = OIDC::Lite::Model::IDToken->new(
        header  => \%header,
        payload => \%payload,
        key     => $key,
    );

    my $params = {
        id_token_hint => $id_token->get_token_string(),
    };

    my $request = Plack::Request->new({
                REQUEST_URI    => q{http://example.org/authorize},
                REQUEST_METHOD => q{GET},
                QUERY_STRING   => build_content($params),
    });

    my $dh = TestDataHandler->new(request => $request);
    my $session_handler = OIDC::Lite::Server::SessionHandler->new(data_handler => $dh);
    ok($session_handler);

    my $res = $session_handler->handle_request();
    ok($res);
    ok($res->{is_valid});
    is($res->{client_id}, 'test_client_id');
    is($res->{javascript_origin_uris}->[0], 'http://example.com');
    is($res->{ops}, 'test_ops');
};
