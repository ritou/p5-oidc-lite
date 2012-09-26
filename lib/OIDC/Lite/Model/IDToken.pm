package OIDC::Lite::Model::IDToken;

use strict;
use warnings;

use base 'Class::Accessor::Fast';
use Params::Validate;
use OIDC::Lite::Util::JWT;

=head1 NAME

OIDC::Lite::Model::IDToken - model class that represents ID token

=head1 ACCESSORS

=head2 header

JWT Header

=head2 payload

JWT Payload

=head2 key

Key for JWT Signature

=cut

__PACKAGE__->mk_accessors(qw(
    header
    payload
    key
    token_string
));

=head1 METHODS

=head2 new( \%header, \%payload, $key )

Constructor

    my $id_token = OIDC::Lite::Model::IDToken->new();
    ...
    my $id_token = OIDC::Lite::Model::IDToken->new(
        header  => \%header,
        payload => \%payload,
        key     => $key,
    );

=cut

sub new {
    my $class = shift;
    my @args = @_ == 1 ? %{$_[0]} : @_;
    my %params = Params::Validate::validate_with(
        params => \@args, 
        spec => {
            header      => { optional => 1 },
            payload     => { optional => 1 },
            key         => { optional => 1 },
        },
        allow_extra => 0,
    );

    my $self = bless \%params, $class;
    unless($self->header){
        my %header=();
        $self->header(\%header);
    }
    unless($self->payload){
        my %payload=();
        $self->payload(\%payload);
    }
 
    return $self;
}

=head2 get_token_string()

generate signarure and return ID Token string.

    my $id_token_string = $id_token->get_token_string();

=cut

sub get_token_string {
    my ($self) = @_;

    $self->header->{typ} = q{JWT}
        unless($self->header->{typ});
    $self->header->{alg} = q{none}
        unless($self->header->{alg});

    # generate token string
    my $jwt = OIDC::Lite::Util::JWT->encode($self->header, $self->payload, $self->key);
    $self->token_string($jwt);
    return $jwt;
}

=head2 load($token_string)

load ID Token object from token string

    my $token_string = 'eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJmb28iOiJiYXIifQ.';
    my $id_token = OIDC::Lite::Model::IDToken->load($token_string);

=cut

sub load {
    my ($self, $token_string) = @_;

    unless($token_string){
        return undef;
    }

    my $header  = OIDC::Lite::Util::JWT->header($token_string);
    my $payload = OIDC::Lite::Util::JWT->payload($token_string);

    if(!$header && !$payload){
        return undef;
    }
    
    my $id_token =  OIDC::Lite::Model::IDToken->new(
                       header   => \%{$header}, 
                       payload  => \%{$payload}, 
                    );
    $id_token->token_string($token_string);
    return $id_token;
}

=head2 verify()

verify token signature.

    my $token_string = '...';
    my $id_token = OIDC::Lite::Model::IDToken->load($token_string);

    my $key = 'shared_secret_key';
    $id_token->key($key);
    unless($id_token->verify()){
        # validation failed
    }

=cut

sub verify {
    my ($self) = @_;
    return 0
        unless($self->token_string);

    $self->key('')
        unless($self->key);

    return OIDC::Lite::Util::JWT->verify($self->token_string, $self->key);
}

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Ryo Ito

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
