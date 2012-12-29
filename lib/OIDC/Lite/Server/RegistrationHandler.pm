package OIDC::Lite::Server::RegistrationHandler;

use strict;
use warnings;

sub new {
    my $class = shift;
    bless {}, $class;
}

sub handle_request {
    my ($self, $data_handler) = @_;
    die "abstract method";
}

=head1 NAME

OIDC::Lite::Server::RegistrationHandler - base class of each registration_type handler

=head1 SYNOPSIS

    my $handler = OIDC::Lite::Server::RegistrationHandler->new;
    my $res = $handler->handle_request( $ctx );

=head1 METHODS

=head2 new

Constructor

=head2 handle_request( $data_handler )

processes passed L<OIDC::Lite::Server::DataHandler>, and return
hash represents that includes response-parameters.

    my $res = $handler->handle_request( $data_handler );

=head1 SEE ALSO

L<OIDC::Lite2::Server::RegistrationHandlers>
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
