use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 11;

use Plack::Request;
use Try::Tiny;
use TestDataHandler;
use OIDC::Lite::Server::RegistrationHandler::RotateSecret;
use OAuth::Lite2::Util qw(build_content);

TestDataHandler->clear;

my $dh = TestDataHandler->new;
my $action = OIDC::Lite::Server::RegistrationHandler::RotateSecret->new;

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
    is($res->{client_secret}, $expected->{client_secret});
    is($res->{registration_access_token}, $expected->{registration_access_token});
    is($res->{expires_at}, $expected->{expires_at});
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
    operation            => q{rotate_secret},
}, {
    client_id   => q{test_client_id},
    client_secret   => q{test_client_secret_rotate},
    registration_access_token   => q{test_registration_access_token_rotate},
    expires_at   => 1234567,
}, {
    access_token_header => q{test_access_token},
});

&test_success({
    operation            => q{rotate_secret},
    access_token => q{test_access_token},
}, {
    client_id   => q{test_client_id},
    client_secret   => q{test_client_secret_rotate},
    registration_access_token   => q{test_registration_access_token_rotate},
    expires_at   => 1234567,
});

&test_error({
    operation            => q{client_rotate},
}, q{invalid_token: });

&test_error({
    operation            => q{client_rotate},
    access_token => q{test_access_token_invalid},
}, q{invalid_token: });

&test_error({
    operation            => q{rotate_secret},
}, 
q{invalid_token: },
{
    access_token_header => q{test_access_token_invalid},
});

