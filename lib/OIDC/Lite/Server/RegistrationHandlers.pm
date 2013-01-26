package OIDC::Lite::Server::RegistrationHandlers;

use strict;
use warnings;

use OIDC::Lite::Server::RegistrationHandler::ClientAssociate;
use OIDC::Lite::Server::RegistrationHandler::ClientUpdate;
use OIDC::Lite::Server::RegistrationHandler::RotateSecret;

my %HANDLERS;

sub add_handler {
    my ($class, $type, $handler) = @_;
    $HANDLERS{$type} = $handler;
}

__PACKAGE__->add_handler( 'client_register' =>
    OIDC::Lite::Server::RegistrationHandler::ClientAssociate->new );
__PACKAGE__->add_handler( 'client_update' =>
    OIDC::Lite::Server::RegistrationHandler::ClientUpdate->new );
__PACKAGE__->add_handler( 'rotate_secret' =>
    OIDC::Lite::Server::RegistrationHandler::RotateSecret->new );

sub get_handler {
    my ($class, $type) = @_;
    return $HANDLERS{$type};
}

=head1 NAME

OIDC::Lite::Server::RegistrationHandlers - store of handlers for each registration type.

=head1 SYNOPSIS

    my $handler = OIDC::Lite::Server::RegistrationHandlers->get_handler( $type );
    $handler->handle_request( $ctx );

=head1 DESCRIPTION

store of handlers for each registration type.

=head1 METHODS

=head2 add_handler( $grant_type, $handler )

=head2 get_handler( $grant_type )

=head1 SEE ALSO

L<OIDC::Lite::Server::RegistrationHandler>
L<OIDC::Lite::Server::RegistrationHandler::ClientAssociate>
L<OIDC::Lite::Server::RegistrationHandler::ClientUpdate>
L<OIDC::Lite::Server::RegistrationHandler::RotateSecret>

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Ryo Ito

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;

