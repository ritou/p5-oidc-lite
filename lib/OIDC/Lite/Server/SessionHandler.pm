package OIDC::Lite::Server::SessionHandler;

use strict;
use warnings;

use Carp ();

sub new {
    my $class = shift;
    my %args = Params::Validate::validate(@_, {
        data_handler => 1,
    });

    my $self = bless {
        data_handler   => $args{data_handler},
    }, $class;
    return $self;
}

sub handle_request {
    my ($self) = @_;

    my $dh = $self->{data_handler};
    my $req = $self->{data_handler}->request;
    my $res = {
        is_valid    => 0,
    };

    # 1. ID Token validation
    my $id_token_hint = $req->param("id_token_hint") or return $res;
    return $res unless ($dh->validate_id_token($id_token_hint));

    my $id_token = OIDC::Lite::Model::IDToken->load($id_token_hint); 

    # 2. Load and validate client_id
    $res->{client_id} = $id_token->payload->{aud};
    return $res unless ($dh->validate_client_by_id($res->{client_id}));

    # 3. Load origin urls
    $res->{javascript_origin_uris} = $dh->get_javascript_origin_uris_from_client_id($res->{client_id}) or return $res;

    # 4. get current ops
    $res->{ops} = $dh->get_ops($res->{client_id}) or return $res;

    $res->{is_valid} = 1;
    return $res;
}

=head1 NAME

OIDC::Lite::Server::SessionHandler - handler for OpenID Connect Session Management

=head1 SYNOPSIS

    # At Check Session Endpoint
    my $handler = OIDC::Lite::Server::SessionHandler->new;
    my $sm_result = $handler->handle_request();
    # sm_result is hash refference includes origin urls, client_id, and opss value.
    
    ...
    

=head1 DESCRIPTION

handler for OpenID Connect authorization request.

=head1 METHODS

=head2 handle_request( $req )

Processes check session request.
If request is valid, return origin_uris and client_id. and ops string.
Your app should rendar HTML and JavaScripts using it.

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Ryo Ito

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
