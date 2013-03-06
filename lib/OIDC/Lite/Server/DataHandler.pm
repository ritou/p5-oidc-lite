package OIDC::Lite::Server::DataHandler;

use strict;
use warnings;

use Params::Validate;
use OAuth::Lite2::Server::Error;
use parent 'OAuth::Lite2::Server::DataHandler';

sub validate_client_for_authorization {
    my ($self, $client_id, $response_type) = @_;
    die "abstract method";
    return 1;
}

sub validate_redirect_uri {
    my ($self, $client_id, $redirect_uri) = @_;
    die "abstract method";
    return 1;
}

sub validate_scope {
    my ($self, $client_id, $scope) = @_;
    die "abstract method";
    return 1;
}

sub validate_display {
    my ($self, $display) = @_;
    die "abstract method";
    return 1;
}

sub validate_prompt {
    my ($self, $prompt) = @_;
    die "abstract method";
    return 1;
}

sub validate_request {
    my ($self, $param) = @_;
    die "abstract method";
    return 1;
}

sub validate_request_uri {
    my ($self, $param) = @_;
    die "abstract method";
    return 1;
}

sub validate_id_token {
    my ($self, $id_token) = @_;
    die "abstract method";
    return 1;
}

sub get_user_id_for_authorization {
    my ($self) = @_;
    die "abstract method";
}

sub create_id_token {
    my ($self) = @_;
    die "abstract method";
    # need another param?
}

sub create_or_update_auth_info {
    my ($self, %args) = @_;
    Params::Validate::validate(@_, {
        client_id   => 1,
        user_id     => 1,
        scope       => { optional => 1 },
        id_token    => { optional => 1 },
    });
    die "abstract method";
}

# methods for Dynamic Client Registration
# spec supported http://openid.net/specs/openid-connect-registration-1_0-14.html
## register and return client metadata
sub client_associate {
    my ($self, $param, $access_token) = @_;
    die "abstract method";
}

## update and return client metadata
sub client_update {
    my ($self, $param, $access_token) = @_;
    die "abstract method";
}

sub rotate_secret {
    my ($self, $access_token) = @_;
    die "abstract method";
}

=head1 NAME

OIDC::Lite::Server::DataHandler - Base class that specifies interface for data handler for your service.

=head1 SYNOPSIS

=head1 DESCRIPTION

This specifies interface to handle data stored on your application.
You have to inherit this, and implements subroutines according to the interface contract.
This is proxy or adapter that connects OIDC::Lite library to your service.

=head1 METHODS

=head2 init

If your subclass need some initiation, implement in this method.

=head1 INTERFACES

=head2 request

Returns <Plack::Request> object.

=head2 validate_client_for_authorization( $client_id, $response_type )

Validation of client and allowed response_type.
If it's OK, return 1. Return 0 if not.

=head2 validate_redirect_uri( $client_id, $redirect_uri )

Validation of redirect_uri param.
If it's OK, return 1. Return 0 if not.

=head2 validate_scope( $client_id, $scope )

Validation of scope param.
If it's OK, return 1. Return 0 if not.

=head2 validate_display( $display )

Validation of display param.
If it's OK, return 1. Return 0 if not.

=head2 validate_prompt( $prompt )

Validation of prompt param.
If it's OK, return 1. Return 0 if not.

=head2 validate_request( $param )

Validation of request param.
If it's OK, return 1. Return 0 if not.

=head2 validate_request_uri( $param )

Validation of request_uri param.
If it's OK, return 1. Return 0 if not.

=head2 get_user_id_for_authorization()

Return current user_id string.

=head2 create_id_token()

Return OIDC::Lite::Model::IDToken object.

=head2 create_or_update_auth_info(%args) 

Return OIDC::Lite::Model::AuthInfo object.

=head2 client_associate($param, $access_token) 

Return OIDC::Lite::Model::ClientInfo object.

=head2 client_update($param, $access_token) 

Return OIDC::Lite::Model::ClientInfo object.

=head2 rotate_secret($access_token)

Return OIDC::Lite::Model::ClientInfo object.

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Ryo Ito

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
