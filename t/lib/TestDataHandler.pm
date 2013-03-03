package TestDataHandler;

use strict;
use warnings;

use parent 'OIDC::Lite::Server::DataHandler';

use String::Random;

use OAuth::Lite2::Server::Error;
use OIDC::Lite::Server::Error;
use OIDC::Lite::Model::AuthInfo;
use OAuth::Lite2::Model::AccessToken;
use OIDC::Lite::Model::IDToken;
use OIDC::Lite::Model::ClientInfo;

my %ID_POD = (
    auth_info    => 0,
    access_token => 0,
    user         => 0,
);

my %AUTH_INFO;
my %ACCESS_TOKEN;
my %DEVICE_CODE;
my %CLIENTS;
my %USERS;

sub clear {
    my $class = shift;
    %AUTH_INFO = ();
    %ACCESS_TOKEN = ();
    %DEVICE_CODE = ();
    %CLIENTS = ();
    %USERS = ();
}

sub gen_next_auth_info_id {
    my $class = shift;
    $ID_POD{auth_info}++;
}

sub gen_next_user_id {
    my $class = shift;
    $ID_POD{user}++;
}

sub gen_next_access_token_id {
    my $class = shift;
    $ID_POD{access_token}++;
}

sub add_client {
    my ($class, %args) = @_;
    $CLIENTS{ $args{id} } = {
        secret  => $args{secret},
        user_id => $args{user_id} || 0,
        response_type => $args{response_type} || 'id_token',
        redirect_uri => $args{redirect_uri} || '',
        scope => $args{scope} || '',
    };
}

sub add_user {
    my ($class, %args) = @_;
    $USERS{ $args{username} } = {
        password => $args{password},
    };
}

sub init {
    my $self = shift;
}

sub get_user_id {
    my ($self, $username, $password) = @_;
    return unless ($username && exists $USERS{$username});
    return unless ($password && $USERS{$username}{password} eq $password);
    return $username;
}

sub get_client_user_id {
    my ($self, $client_id) = @_;
    return unless ($client_id && exists $CLIENTS{$client_id});
    return $CLIENTS{$client_id}{user_id};
}

# TODO needed?
sub get_client_by_id {
    my ($self, $client_id) = @_;
    return unless ($client_id && exists $CLIENTS{$client_id});
    return $CLIENTS{$client_id};
}

# called in following flows:
#   - refresh
sub get_auth_info_by_refresh_token {
    my ($self, $refresh_token) = @_;

    for my $id (keys %AUTH_INFO) {
        my $auth_info = $AUTH_INFO{$id};
        return $auth_info if $auth_info->{refresh_token} eq $refresh_token;
    }
    return;
}

sub get_auth_info_by_id {
    my ($self, $auth_id) = @_;
    return $AUTH_INFO{$auth_id};
}

# called in following flows:
#   - device_token
sub get_auth_info_by_code {
    my ($self, $device_code) = @_;
    for my $id (keys %AUTH_INFO) {
        my $auth_info = $AUTH_INFO{$id};
        return $auth_info if ($auth_info->code && $auth_info->code eq $device_code);
    }
    return;
}

sub create_or_update_auth_info {
    my ($self, %params) = @_;

    my $client_id    = $params{client_id};
    my $user_id      = $params{user_id};
    my $scope        = $params{scope};
    my $code         = $params{code};
    my $redirect_uri = $params{redirect_uri};
    my $id_token     = $params{id_token};

    my $id = ref($self)->gen_next_auth_info_id();
    my $refresh_token = sprintf q{refresh_token_%d}, $id;
    $id_token = sprintf q{id_token_%d}, $id
                    unless($id_token);
    $code = sprintf q{code_%d}, $id
                    unless($code);
    my @claims = (q{user_id}, q{email});

    my $auth_info = OIDC::Lite::Model::AuthInfo->new({
        id              => $id,
        client_id       => $client_id,
        user_id         => $user_id,
        scope           => $scope,
        refresh_token   => $refresh_token,
        id_token        => $id_token,
        userinfo_claims => \@claims,
    });
    $auth_info->code($code) if $code;
    $auth_info->redirect_uri($redirect_uri) if $redirect_uri;

    $AUTH_INFO{$id} = $auth_info;

    return $auth_info;
}

# called in following flows:
#   - refresh
sub create_or_update_access_token {
    my ($self, %params) = @_;

    my $auth_info = $params{auth_info};
    my $auth_id = $auth_info->id;

    my $id = ref($self)->gen_next_access_token_id();
    my $token = sprintf q{access_token_%d}, $id;

    my %attrs = (
        auth_id    => $auth_id,
        token      => $token,
        expires_in => $params{expires_in} || 3600,
        created_on => time(),
    );

    my $access_token = OAuth::Lite2::Model::AccessToken->new(\%attrs);
    $ACCESS_TOKEN{$auth_id} = $access_token;
    return $access_token;
}

sub get_access_token {
    my ($self, $token) = @_;
    for my $auth_id ( keys %ACCESS_TOKEN ) {
        my $t = $ACCESS_TOKEN{ $auth_id };
        if ($t->token eq $token) {
            return $t;
        }
    }
    return;
}

sub validate_client {
    my ($self, $client_id, $client_secret, $type) = @_;
    return 0 unless exists $CLIENTS{ $client_id };
    my $client = $CLIENTS{ $client_id };
    return 0 unless $client->{secret} eq $client_secret;

    if ($client_id eq 'aaa') {
        if ($type eq 'basic-credentials') {
            return 1;
        } else {
            return 0;
        }
    } else {
        return 1;
    }
}

sub validate_client_by_id {
    my ($self, $client_id) = @_;
    return ($client_id ne 'malformed');
}

sub validate_user_by_id {
    my ($self, $user_id) = @_;
    return ($user_id ne 666);
}

# OIDC additional methods
sub validate_client_for_authorization {
    my ($self, $client_id, $response_type) = @_;
    return 0 unless exists $CLIENTS{ $client_id };
    my $client = $CLIENTS{ $client_id };
    return 0 unless ($response_type && $client->{response_type} );
    return 0 unless $client->{response_type} eq $response_type;
    return 1;
}

sub validate_redirect_uri {
    my ($self, $client_id, $redirect_uri) = @_;
    return 0 unless exists $CLIENTS{ $client_id };
    return 0 unless ($redirect_uri);
    my $client = $CLIENTS{ $client_id };
    return 0 unless ($redirect_uri && $client->{redirect_uri} );
    return 0 unless $client->{redirect_uri} eq $redirect_uri;
    return 1;
}

sub validate_scope{
    my ($self, $client_id, $scope) = @_;
    return 0 unless exists $CLIENTS{ $client_id };
    return 0 unless ($scope);
    my $client = $CLIENTS{ $client_id };
    return 0 unless ($scope && $client->{scope} );
    return 0 unless $client->{scope} eq $scope;
    return 1;
}

sub validate_display{
    my ($self, $display) = @_;
    return (!$display || $display ne "invalid");
}

sub validate_prompt{
    my ($self, $prompt) = @_;
    return (!$prompt || $prompt ne "invalid");
}

sub validate_request{
    my ($self, $param) = @_;
    return (!$param->{request} || $param->{request} ne "invalid");
}

sub validate_request_uri{
    my ($self, $param) = @_;
    return (!$param->{request_uri} || $param->{request_uri} ne "invalid");
}

sub validate_id_token{
    my ($self, $id_token) = @_;
    return (!$id_token || $id_token ne "invalid");
}

sub get_user_id_for_authorization {
    my ($self) = @_;
    return 1;
}

sub create_id_token {
    my ($self) = @_;
    my %header =    (
                        typ =>'JWT',
                        alg => 'HS256',
                    );
    my %payload =   (
                        iss     => 'issstr',
                        user_id => '1',
                        aud     => 'audstr',
                        exp     => 1349257197 + 600,
                        iat     => 1349257197,
                    );
    my $key = q{this_is_shared_secret_key};
    return OIDC::Lite::Model::IDToken->new(
        header  => \%header,
        payload => \%payload,
        key     => $key,
    );
}

sub client_associate {
    my ($self, $param, $access_token) = @_;
   
    # check access token 
    OAuth::Lite2::Server::Error::InvalidToken->throw(
    ) if($access_token and $access_token ne 'test_access_token');
 
    # check redirect_uri
    OIDC::Lite::Server::Error::InvalidRedirectUri->throw(
    ) if($param->{redirect_uris} ne 'http://example.org/redirect');

    # configuration parameter
    return if($param->{application_type} and $param->{application_type} eq 'invalid');
 
    # success
    my $client_info = OIDC::Lite::Model::ClientInfo->new(
        client_id => q{test_client_id},
        client_secret => q{test_client_secret},
        registration_access_token => q{test_registration_access_token},
        expires_at => 1234567,
        metadata => {
            redirect_uris => $param->{redirect_uris},
        }
    );
    return $client_info;
}

sub client_update {
    my ($self, $param, $access_token) = @_;
   
    # check redirect_uri
    OIDC::Lite::Server::Error::InvalidRedirectUri->throw(
    ) if($param->{redirect_uris} ne 'http://example.org/redirect');

    # configuration parameter
    return if($param->{application_type} and $param->{application_type} eq 'invalid');

    # success
    my $client_info = OIDC::Lite::Model::ClientInfo->new(
        client_id => q{test_client_id},
        client_secret => q{test_client_secret},
        registration_access_token => q{test_registration_access_token},
        expires_at => 1234567,
        metadata => {
            redirect_uris => $param->{redirect_uris},
        }
    );
    return $client_info;
}

sub rotate_secret {
    my ($self, $access_token) = @_;
   
    # configuration parameter
    return if(!$access_token or $access_token ne qw{test_access_token});
 
    # success
    my $client_info = OIDC::Lite::Model::ClientInfo->new(
        client_id => q{test_client_id},
        client_secret => q{test_client_secret_rotate},
        registration_access_token => q{test_registration_access_token_rotate},
        expires_at => 1234567
    );
    return $client_info;
}

# methods for Session Management
sub get_javascript_origin_uris_from_client_id{
    my ($self, $client_id) = @_;
    return if ($client_id eq 'malformed');
    return ['http://example.com'];
}

sub get_ops{
    my ($self, $client_id) = @_;
    return '' unless ($client_id eq 'test_client_id');
    return 'test_ops';
}

1;
