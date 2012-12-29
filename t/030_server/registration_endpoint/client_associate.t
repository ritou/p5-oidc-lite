use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 18;

use Plack::Request;
use Try::Tiny;
use TestDataHandler;
use OIDC::Lite::Server::RegistrationHandler::ClientAssociate;
use OAuth::Lite2::Util qw(build_content);

TestDataHandler->clear;

my $dh = TestDataHandler->new;
my $action = OIDC::Lite::Server::RegistrationHandler::ClientAssociate->new;

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
    type            => q{client_associate},
    redirect_uris  => q{http://example.org/redirect},
}, {
    client_id   => q{test_client_id},
    client_secret   => q{test_client_secret},
    registration_access_token   => q{test_registration_access_token},
    expires_at   => 1234567,
});

# with access token
&test_success({
    type            => q{client_associate},
    redirect_uris  => q{http://example.org/redirect},
}, {
    client_id   => q{test_client_id},
    client_secret   => q{test_client_secret},
    registration_access_token   => q{test_registration_access_token},
    expires_at   => 1234567,
}, {
    access_token_header => q{test_access_token},
});

&test_success({
    type            => q{client_associate},
    redirect_uris  => q{http://example.org/redirect},
    access_token => q{test_access_token},
}, {
    client_id   => q{test_client_id},
    client_secret   => q{test_client_secret},
    registration_access_token   => q{test_registration_access_token},
    expires_at   => 1234567,
});


&test_error({
    type            => q{client_associate},
}, q{invalid_redirect_uri: 'redirect_uris' is missing});

&test_error({
    type            => q{client_associate},
    access_token => q{test_access_token},
    redirect_uris  => q{http://example.org/redirect},
}, 
q{invalid_request: Both Authorization header and payload includes access token.},
{
    access_token_header => q{test_access_token},
});

&test_error({
    type            => q{client_associate},
    redirect_uris  => q{http://example.org/redirect},
}, 
q{invalid_token: },
{
    access_token_header => q{invalid_access_token},
});

&test_error({
    type            => q{client_associate},
    redirect_uris  => q{http://example.org/redirect},
    access_token => q{invalid_access_token},
}, 
q{invalid_token: });

&test_error({
    type            => q{client_associate},
    redirect_uris  => q{http://example.org/redirect_invalid},
}, 
q{invalid_redirect_uri: });

&test_error({
    type            => q{client_associate},
    redirect_uris  => q{http://example.org/redirect},
    application_type => q{invalid},
}, 
q{invalid_configuration_parameter: });
