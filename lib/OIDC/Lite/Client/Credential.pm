package OIDC::Lite::Client::Credential;

use strict;
use warnings;

use base 'Class::Accessor::Fast';

__PACKAGE__->mk_accessors(qw(
    client_id
    client_secret
    registration_access_token
    expires_at
));

=head1 NAME

OIDC::Lite::Client::Credential - Class represents dynamic client registration response

=head1 SYNOPSIS

    my $t = $client->associate( ... );
    $t->client_id;
    $t->client_secret;
    $t->registration_access_token;
    $t->expires_at;

=head1 DESCRIPTION

Class represents registration response

See
http://openid.net/specs/openid-connect-registration-1_0-14.html#anchor4

=head1 ACCESSORS

=head2 client_id

=head2 client_secret

=head2 registration_access_token

=head2 expires_at

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Ryo Ito

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
