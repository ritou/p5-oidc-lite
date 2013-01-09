package OIDC::Lite::Util::JWT;

use strict;
use warnings;

use Try::Tiny;
use Params::Validate;
use parent 'Acme::JWT';
use JSON qw/decode_json encode_json/;
use MIME::Base64 qw/encode_base64url decode_base64url/;

use constant {
    JWT_ALG_LEN     => 2,
    JWT_BITS_LEN    => 3,
    JWT_ALG_NONE    => q{none},
    JWT_ALG_HMAC    => q{HS},
    JWT_ALG_RSA     => q{RS},
    JWT_ALG_ECDSA   => q{ES},
};

=head1 NAME

OIDC::Lite::Util::JWT - JSON Web Token

=head1 SYNOPSIS

TBD

=head1 DESCRIPTION

JSON Web Token utility class.

=head1 METHODS

=head2 encode( \%header, \%payload, $key )

Encode components and return JWT string

    # none
    my %header =    (
                        alg => 'none',
                        typ => 'JWS',
                    );
    my %payload =   (
                        foo => 'bar'
                    );
    my $key = '';
    my $jwt = OIDC::Lite::Util::JWT->encode(\%header, \%payload, $key);
    
    # HS256
    %header =    (
                        alg => 'HS256',
                        typ => 'JWS',
                    );
    %payload =   (
                        foo => 'bar'
                    );
    $key = q{this_is_shared_secret_key};
    $jwt = OIDC::Lite::Util::JWT->encode(\%header, \%payload, $key);
    
    # RS256
    %header =    (
                        alg => 'RS256',
                        typ => 'JWS',
                    );
    %payload =   (
                        foo => 'bar'
                    );
    $privkey = (you private key string);
    $jwt = OIDC::Lite::Util::JWT->encode(\%header, \%payload, $privkey);

=cut

sub encode {
    my $self = shift;
    my ($header, $payload, $key) = @_;
    my $algorithm = defined($header->{alg}) ? $header->{alg} : JWT_ALG_NONE;

    my $segments = [];
    push(@$segments, encode_base64url(encode_json($header)));
    push(@$segments, encode_base64url(encode_json($payload)));
    my $signing_input = join('.', @$segments);

    unless ($algorithm eq JWT_ALG_NONE) {
        my $signature = $self->sign($algorithm, $key, $signing_input);
        push(@$segments, encode_base64url($signature));
    } else {
        push(@$segments, '');
    }
    return join('.', @$segments);
}

=head2 verify( $token_string, $key )

Verify JWT Signature with key

    my $jwt = '(JWT string)';
    if(OIDC::Lite::Util::JWT->verify($jwt, $key){
        # valid
    }else{
        # invalid
    }

=cut

sub verify{
    my $self = shift;
    my ($token_string, $key) = @_;
    my $segments = [split(/\./, $token_string)];
    return 0
        unless (@$segments == 2 or @$segments == 3);
    
    push(@$segments, '') if(@$segments == 2);
    my ($header_segment, $payload_segment, $crypt_segment) = @$segments;
    my $header = decode_json(decode_base64url($header_segment));

    my $algorithm = defined($header->{alg}) ? $header->{alg} : JWT_ALG_NONE;
    return 0 unless ($algorithm eq JWT_ALG_NONE || $self->valid_algorithm($algorithm));

    my $signing_input = $header_segment.'.'.$payload_segment;
    unless ($algorithm eq JWT_ALG_NONE) {
        my $alg_prefix = substr($algorithm, 0, JWT_ALG_LEN);
        if($alg_prefix eq JWT_ALG_HMAC){
            my $signature = $self->sign($algorithm, $key, $signing_input);
            return ($crypt_segment eq encode_base64url($signature));
        }elsif($alg_prefix eq JWT_ALG_RSA){
            my $signature = decode_base64url($crypt_segment);
            return $self->verify_rsa($algorithm, $key, $signing_input, $signature);
        }else{
            # ES is not supported
            return 0;
        }
    } else {
        return ($crypt_segment eq '');
    }

    return ($token_string eq join('.', @$segments));
}

sub valid_algorithm{
    my $self = shift;
    my ($algorithm) = @_;
    return 0 unless(length($algorithm) == 5);

    my $alg_prefix = substr($algorithm, 0, JWT_ALG_LEN);
    return 0 unless($alg_prefix eq JWT_ALG_HMAC or 
                    $alg_prefix eq JWT_ALG_RSA  or
                    $alg_prefix eq JWT_ALG_ECDSA);

    my $alg_bits = substr($algorithm, JWT_ALG_LEN, JWT_BITS_LEN);
    return 0 unless($alg_bits eq '256' or 
                    $alg_bits eq '384' or
                    $alg_bits eq '512');
    return 1;
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
        return {} if defined $_;
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
        return {} if defined $_;
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
