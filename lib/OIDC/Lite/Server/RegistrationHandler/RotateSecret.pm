package OIDC::Lite::Server::RegistrationHandler::RotateSecret;

use strict;
use warnings;

use parent 'OIDC::Lite::Server::RegistrationHandler';
use OIDC::Lite::Server::Error;
use OIDC::Lite::Model::ClientInfo;
use OAuth::Lite2::ParamMethod::AuthHeader;
use Carp ();

sub handle_request {
    my ($self, $dh) = @_;

    my $req = $dh->request;
    my $parser = OAuth::Lite2::ParamMethod::AuthHeader->new;
    my ($access_token, $params);

    if($parser->match($req)){
        ($access_token, $params) = $parser->parse($req);
    }
    # access token check
    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "Both Authorization header and payload includes access token."
    ) if ($access_token and $req->param('access_token'));

    $params = $req->parameters->mixed;
    $access_token = $params->{access_token} if ($params->{access_token});
    my $client_info = $dh->rotate_secret($access_token)
        or OAuth::Lite2::Server::Error::InvalidToken->throw;

    Carp::croak "OIDC::Lite::Server::DataHandler::rotate_secret doesn't return OIDC::Lite::Model::ClientInfo"
        unless ($client_info && $client_info->isa("OIDC::Lite::Model::ClientInfo"));

    my $res = {
        client_id => $client_info->client_id,
        client_secret => $client_info->client_secret,
        registration_access_token => $client_info->registration_access_token,
        expires_at => $client_info->expires_at,
    };

    return $res;
}

=head1 NAME

OIDC::Lite::Server::RegistrationHandler::RotateSecret - handler for 'rotate_secret' registration type request

=head1 SYNOPSIS

    my $handler = OIDC::Lite::Server::RegistrationHandler::RotateSecret->new;
    my $res = $handler->handle_request( $data_handler );

=head1 DESCRIPTION

handler for 'rotate_secret' registration type request.

=head1 METHODS

=head2 handle_request( $req )

See L<OAuth::Lite2::Server::RegistrationHandler> document.

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Ryo Ito

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
