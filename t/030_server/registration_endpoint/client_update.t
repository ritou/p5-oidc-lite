use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 8;

use Plack::Request;
use Try::Tiny;
use TestDataHandler;
use OIDC::Lite::Server::RegistrationHandler::ClientUpdate;
use OAuth::Lite2::Util qw(build_content);

TestDataHandler->clear;

my $dh = TestDataHandler->new;
my $action = OIDC::Lite::Server::RegistrationHandler::ClientUpdate->new;

sub test_success {
    my $params = shift;
    my $expected = shift;
    my $optional = shift;
    my $request = Plack::Request->new({
        REQUEST_URI    => q{http://example.org/registration},
        REQUEST_METHOD => q{GET},
        QUERY_STRING   => build_content($params),
    });
    $request->header("Authorization" => sprintf(q{Bearer %s}, $optional->{access_token_header})) if ($optional->{access_token_header});

    my $dh = TestDataHandler->new(request => $request);
    my $res; try {
        $res = $action->handle_request($dh);
    } catch {
        my $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };

    is($res->{client_id}, $expected->{client_id});
    is($res->{redirect_uris}, $expected->{redirect_uris});
}

sub test_error {
    my $params = shift;
    my $message = shift;
    my $optional = shift;
    my $request = Plack::Request->new({
        REQUEST_URI    => q{http://example.org/registration},
        REQUEST_METHOD => q{GET},
        QUERY_STRING   => build_content($params),
    });
    $request->header("Authorization" => sprintf(q{Bearer %s}, $optional->{access_token_header})) if ($optional->{access_token_header});
    my $dh = TestDataHandler->new(request => $request);
    my $error_message; try {
        my $res = $action->handle_request($dh);
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };

    like($error_message, qr/$message/);
}

# success
&test_success({
    operation            => q{client_update},
    redirect_uris   => q{http://example.org/redirect},
    access_token    => q{test_registration_access_token},
}, {
    client_id   => q{test_client_id},
    redirect_uris   => q{http://example.org/redirect},
});

&test_success({
    operation            => q{client_update},
    redirect_uris  => q{http://example.org/redirect},
}, {
    client_id   => q{test_client_id},
    redirect_uris   => q{http://example.org/redirect},
}, {
    access_token_header => q{test_access_token},
});

&test_error({
    operation            => q{client_update},
}, q{invalid_token: });

&test_error({
    operation            => q{client_update},
    redirect_uris  => q{http://example.org/redirect},
    access_token    => q{test_registration_access_token},
}, q{invalid_request: Both Authorization header and payload includes access token.}, {
    access_token_header => q{test_access_token},
});

&test_error({
    operation            => q{client_update},
    access_token    => q{test_registration_access_token},
}, q{invalid_redirect_uri: 'redirect_uris' is missing});

&test_error({
    operation            => q{client_update},
    redirect_uris  => q{http://example.org/redirect_invalid},
    access_token    => q{test_registration_access_token},
}, q{invalid_redirect_uri: });
