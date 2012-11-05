package OIDC::Lite::Util::JWT;

use strict;
use warnings;

use Params::Validate;
use parent 'Acme::JWT';
use JSON qw/decode_json encode_json/;
use MIME::Base64 qw/encode_base64url decode_base64url/;

=head1 NAME

OIDC::Lite::Util::JWT - JSON Web Token

=head1 SYNOPSIS

TBD

=head1 DESCRIPTION

JSON Web Token utility class.

=cut

sub encode {
    my $self = shift;
    my ($header, $payload, $key) = @_;
    my $algorithm = defined($header->{alg}) ? $header->{alg} : q{none};

    my $segments = [];
    push(@$segments, encode_base64url(encode_json($header)));
    push(@$segments, encode_base64url(encode_json($payload)));
    my $signing_input = join('.', @$segments);

    unless ($algorithm eq q{none}) {
        my $signature = $self->sign($algorithm, $key, $signing_input);
        push(@$segments, encode_base64url($signature));
    } else {
        push(@$segments, '');
    }
    return join('.', @$segments);
}

sub verify{
    # token string, key
    my $self = shift;
    my ($token_string, $key) = @_;
    my $segments = [split(/\./, $token_string)];
    return ''
        unless (@$segments == 2 or @$segments == 3);
    
    pop(@$segments) if(@$segments == 3);
    my ($header_segment, $payload_segment, $crypt_segment) = @$segments;
    my $header = decode_json(decode_base64url($header_segment));
    my $algorithm = defined($header->{alg}) ? $header->{alg} : q{none};

    my $signing_input = $header_segment.'.'.$payload_segment;
    unless ($algorithm eq q{none}) {
        my $signature = $self->sign($algorithm, $key, $signing_input);
        push(@$segments, encode_base64url($signature));
    } else {
        push(@$segments, '');
    }
    return ($token_string eq join('.', @$segments));
}

sub header {
    my $self = shift;
    my ($jwt) = @_;
    my $segments = [split(/\./, $jwt)];
    return {}
        unless (@$segments == 2 or @$segments == 3);

    my ($header_segment, $payload_segment, $crypt_segment) = @$segments;
    my $header;
    try {
        $header = decode_json(decode_base64url($header_segment));
    } catch {
        return $header;
    };
}

sub payload {
    my $self = shift;
    my ($jwt) = @_;
    my $segments = [split(/\./, $jwt)];
    return {}
        unless (@$segments == 2 or @$segments == 3);

    my ($header_segment, $payload_segment, $crypt_segment) = @$segments;
    my $payload;
    try {
        $payload = decode_json(decode_base64url($payload_segment));
    } catch {
        return $payload;
    };
}

=head1 SEE ALSO

L<Acme::JWT>

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
