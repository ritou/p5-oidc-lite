package OIDC::Lite::Server::AuthorizationHandler;

use strict;
use warnings;

use OAuth::Lite2::Server::Error;
use Carp ();
use Data::Dumper;

sub new {
    my $class = shift;
    my %args = Params::Validate::validate(@_, {
        data_handler => 1,
        response_types => 1,
    });

    my $self = bless {
        data_handler   => $args{data_handler},
        response_types   => $args{response_types},
    }, $class;
    return $self;
}

sub handle_request {
    my ($self) = @_;
    my $dh = $self->{data_handler};
    my $req = $self->{data_handler}->request;

    # response_type
    my $allowed_response_type = $self->{response_types};
    my $response_type = $req->param("response_type")
        or OAuth::Lite2::Server::Error::InvalidRequest->throw(
            description => "'response_type' not found"
        );

    my @response_type_for_sort = split(/\s/, $response_type);
    @response_type_for_sort = sort @response_type_for_sort;
    $response_type = join(' ', @response_type_for_sort);

    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "'response_type' not allowed"
    ) unless (grep { $_ eq $response_type } @$allowed_response_type);
 
    # client_id 
    my $client_id = $req->param("client_id")
        or OAuth::Lite2::Server::Error::InvalidClient->throw(
            description => "'client_id' not found"
    );

    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "'response_type' not allowed for this 'client_id'"
    ) unless ($dh->validate_client_for_authorization($client_id, $response_type));

    # redirect_uri
    my $redirect_uri = $req->param("redirect_uri")
        or OAuth::Lite2::Server::Error::InvalidRequest->throw(
            description => "'redirect_uri' not found"
    );
    
    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "'redirect_uri' is invalid"
    ) unless ($dh->validate_redirect_uri($client_id, $redirect_uri));

    # scope
    my $scope = $req->param("scope");
    OAuth::Lite2::Server::Error::InvalidScope->throw
        unless ($dh->validate_scope($client_id, $scope));

    # nonce
    my $nonce = $req->param("nonce");
    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "nonce_required"
    ) if (!$nonce && $response_type ne "token" && $response_type ne "code");

    # display
    my $display = $req->param("display");
    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "'display' is invalid"
    ) unless ($dh->validate_display($display));

    # prompt
    my $prompt = $req->param("prompt");
    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "'prompt' is invalid"
    ) unless ($dh->validate_prompt($prompt));

    # request
    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "'request' is invalid"
    ) unless ($dh->validate_request($req->parameters()));

    # request_uri
    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "'request_uri' is invalid"
    ) unless ($dh->validate_request_uri($req->parameters()));

    # id_token
    my $id_token = $req->param("id_token");
    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "'id_token' is invalid"
    ) unless ($dh->validate_id_token($id_token));
}

sub allow {
    my ($self) = @_;
    my $dh = $self->{data_handler};
    my $req = $self->{data_handler}->request;

    my $client_id = $req->param("client_id");
    my $user_id = $dh->get_user_id_for_authorization();
    my $scope = $req->param("scope");

    # create id_token
    my $id_token = $dh->create_id_token();

    # create authInfo
    my $auth_info = $dh->create_or_update_auth_info(
                        client_id       => $client_id,
                        user_id         => $user_id,
                        scope           => $scope,
                        id_token        => $id_token->get_token_string(),
    );

    # create Access Token
    my $access_token;
    $access_token = $dh->create_or_update_access_token(
                        auth_info => $auth_info,
    ) if (
        $req->param("response_type") eq 'token' ||
        $req->param("response_type") eq 'code token' ||
        $req->param("response_type") eq 'id_token token' ||
        $req->param("response_type") eq 'code id_token token'
    );
  
    my $params = {};
    # state
    $params->{state} = $req->param("state")
        if($req->param("state"));
 
    # access token
    if($access_token){
        $params->{access_token} = $access_token->token; 
        $params->{token_type} = q{Bearer}; 
        $params->{expires_in} = $access_token->expires_in
                                    if $access_token->expires_in;
    }

    # authorization code
    $params->{code} = $auth_info->code
        if (
            $req->param("response_type") eq 'code' ||
            $req->param("response_type") eq 'code token' ||
            $req->param("response_type") eq 'code id_token' ||
            $req->param("response_type") eq 'code id_token token'
        );

    # id_token
    $params->{id_token} = $auth_info->id_token
        if (
            $req->param("response_type") eq 'id_token' ||
            $req->param("response_type") eq 'code id_token' ||
            $req->param("response_type") eq 'id_token token' ||
            $req->param("response_type") eq 'code id_token token'
        );

    # build response
    my $res = {
        redirect_uri => $req->param("redirect_uri"),
    };

    # set data to query or fragment
    if($req->param("response_type") eq 'code'){
        $res->{query} = $params;
    }else{
        $res->{fragment} = $params;
    }
    return $res;
}

sub deny {
    my ($self) = @_;
    my $dh = $self->{data_handler};
    my $req = $self->{data_handler}->request;

    my $params = {
        error => q{access_denied},
    };
    
    $params->{state} = $req->param("state")
        if($req->param("state"));

    my $res = {
        redirect_uri => $req->param("redirect_uri"),
    };

    # build response
    if($req->param("response_type") eq 'code'){
        $res->{query} = $params;
    }else{
        $res->{fragment} = $params;
    }
    return $res;
}

=head1 NAME

OIDC::Lite::Server::AuthorizationHandler - handler for OpenID Connect Authorization request

=head1 SYNOPSIS

    # At Authorization Endpoint
    my $handler = OIDC::Lite::Server::AuthorizationHandler->new;
    $handler->handle_request();

    # after user agreement
    my $res;
    if($allowed){
        $res = $handler->allow();        
    }else{
        $res = $handler->deny();
    }
    ...

=head1 DESCRIPTION

handler for OpenID Connect authorization request.

=head1 METHODS

=head2 handle_request( $req )

Processes authorization request.
If there is error, L<OAuth::Lite2::Server::Error> object is thrown.

=head2 allow( $req )

Returns authorization response params.

=head2 deny( $req )

Returns authorization error response params.

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Ryo Ito

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;