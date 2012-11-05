use strict;
use warnings;

use Test::More tests => 12;

use lib 't/lib';
use TestPR;
use TestDataHandler;
use Try::Tiny;
use HTTP::Response;
use HTTP::Request;
use HTTP::Message::PSGI;

my $dh = TestDataHandler->new;

my $auth_info = $dh->create_or_update_auth_info(
    client_id    => q{foo},
    user_id      => q{1},
    scope        => q{email},
    code         => q{code_bar},
    redirect_uri => q{http://example.org/callback},
);

my $access_token = $dh->create_or_update_access_token(
    auth_info => $auth_info,
);

my $app = TestPR->new;

sub request {
    my $req = shift;
    my $res = try {
        HTTP::Response->from_psgi($app->($req->to_psgi));
    } catch {
        HTTP::Response->from_psgi([500, ["Content-Type" => "text/plain"], [ $_ ]]);
    };
    return $res;
}

my ($req, $res);
# LEGACY
$req = HTTP::Request->new("GET" => q{http://example.org/});
$req->header("Authorization" => sprintf(q{OAuth %s}, $access_token->token));
$res = &request($req);
ok($res->is_success, 'request should not fail');
is($res->content, q{{user: '1', scope: 'email', claims: ["user_id","email"], is_legacy: '1'}}, 'successful response');

$req = HTTP::Request->new("POST" => q{http://example.org/});
$req->content_type('application/x-www-form-urlencoded');
$req->content(sprintf(q{oauth_token=%s}, $access_token->token));
$res = &request($req);
ok($res->is_success, 'request should not fail');
is($res->content, q{{user: '1', scope: 'email', claims: ["user_id","email"], is_legacy: '1'}}, 'successful response');

$req = HTTP::Request->new("GET" => sprintf(q{http://example.org/?oauth_token=%s}, $access_token->token));
$res = &request($req);
ok($res->is_success, 'request should not fail');
is($res->content, q{{user: '1', scope: 'email', claims: ["user_id","email"], is_legacy: '1'}}, 'successful response');

# RFC
$req = HTTP::Request->new("GET" => q{http://example.org/});
$req->header("Authorization" => sprintf(q{Bearer %s}, $access_token->token));
$res = &request($req);
ok($res->is_success, 'request should not fail');
is($res->content, q{{user: '1', scope: 'email', claims: ["user_id","email"], is_legacy: '0'}}, 'successful response');

$req = HTTP::Request->new("POST" => q{http://example.org/});
$req->content_type('application/x-www-form-urlencoded');
$req->content(sprintf(q{access_token=%s}, $access_token->token));
$res = &request($req);
ok($res->is_success, 'request should not fail');
is($res->content, q{{user: '1', scope: 'email', claims: ["user_id","email"], is_legacy: '0'}}, 'successful response');

$req = HTTP::Request->new("GET" => sprintf(q{http://example.org/?access_token=%s}, $access_token->token));
$res = &request($req);
ok($res->is_success, 'request should not fail');
is($res->content, q{{user: '1', scope: 'email', claims: ["user_id","email"], is_legacy: '0'}}, 'successful response');

