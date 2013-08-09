package OIDC::Lite::Util::Base64;
use strict;
use warnings;

use parent 'Exporter';
use MIME::Base64 qw/encode_base64 decode_base64/;

our @EXPORT = qw/encode_base64url decode_base64url/;

=head1 NAME

OIDC::Lite::Util::Base64 - Base64 url encoder/decoder

=head1 SYNOPSIS

    use OIDC::Lite::Util::Base64 qw/encode_base64url decode_base64url/;

=head1 DESCRIPTION

Base64 URL encode/decode methods for older version( < 3.11 ) of L<MIME::Base64> module

=cut
sub encode_base64url {
    my $e = encode_base64(shift, "");
    $e =~ s/=+\z//;
    $e =~ tr[+/][-_];
    return $e;
}
 
sub decode_base64url {
    my $s = shift;
    $s =~ tr[-_][+/];
    $s .= '=' while length($s) % 4;
    return decode_base64($s);
}

=head1 AUTHOR

Ryo Ito E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Ryo Ito

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
