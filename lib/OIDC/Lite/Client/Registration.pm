package OIDC::Lite::Client::Registration;

use strict;
use warnings;

use base 'Class::ErrorHandler';

use Params::Validate qw(HASHREF);
use Carp ();
use bytes ();
use URI;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Headers;
use Try::Tiny;

use OIDC::Lite;
use OAuth::Lite2::Util qw(build_content);
use OAuth::Lite2::Formatters;
use OIDC::Lite::Client::RegistrationResponseParser;
use MIME::Base64 qw(encode_base64);

use constant REQUIRE_REGISTRATION_ACCESS_TOKEN => 1;

=head1 NAME

OIDC::Lite::Client::Registration - OpenID Connect Dynamic Client Registration Client

=head1 SYNOPSIS

    my $client = OIDC::Lite::Client::Registration->new(
        registration_endpoint   => q{op_registration_url},
    );

    my $config = {
        redirect_uris => q{https://openidconnect.info/rp},
        application_name => q{test_app_name},
    };

    my $your_app = shift;

    # Client Registration

    my $client_credential = $client->associate(
        metadata => $config,
    ) or return $your_app->error( $client->errstr );

    $your_app->store->save( client_id                   => $client_credentials->client_id  );
    $your_app->store->save( client_secret               => $client_credentials->client_secret );
    $your_app->store->save( registration_access_token   => $client_credentials->registration_access_token );

    # Client Update
    my $updated_client = $client->update(
        access_token => $client_credential->registration_access_token,
        metadata => $config,
    ) or return $your_app->error( $client->errstr );

    # Rotate Secret
    my $client_credentials_new = $client->rotate_secret(
        access_token => $client_credential->registration_access_token,
    ) or return $your_app->error( $client->errstr );
    $your_app->store->save( client_secret               => $client_credentials_new->client_secret );
    $your_app->store->save( registration_access_token   => $client_credentials_new->registration_access_token );

=head1 DESCRIPTION

Client library for OpenID Connect Dynamic Client Registration

=head1 METHODS

=head2 new( %params )

=over 4

=item registration_endpoint

Registration Endpoint URL

=item agent

user agent. if you omit this, LWP::UserAgent's object is set by default.
You can use your custom agent or preset-agents.

See also

L<OAuth::Lite2::Agent::Dump>
L<OAuth::Lite2::Agent::Strict>
L<OAuth::Lite2::Agent::PSGIMock>

=back

=cut

sub new {

    my $class = shift;

    my %args = Params::Validate::validate(@_, {
        registration_endpoint   => 1,
        agent             => { optional => 1 },
    });

    my $self = bless {
        registration_endpoint  => undef,
        last_request      => undef,
        last_response     => undef,
        %args,
    }, $class;

    unless ($self->{agent}) {
        $self->{agent} = LWP::UserAgent->new;
        $self->{agent}->agent(
            join "/", __PACKAGE__, $OIDC::Lite::VERSION);
    }

    $self->{format} ||= 'json';
    $self->{response_parser} = OIDC::Lite::Client::RegistrationResponseParser->new;

    return $self;
}

=head2 associate( %params )

execute client association
and returns L<OIDC::Lite::Client::Credential> object.

=over 4

=item access_token

Access Token obtained out of band to authorize the registrant.

=item metadata

Configuration parameters

=back

=cut

sub associate {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        metadata        => { type => HASHREF },
        access_token    => { optional => 1 },
    });
    Carp::croak "redirect_uris not found" unless (exists $args{metadata}{redirect_uris});

    my %params = (
        operation            => 'client_register',
    );
    for my $key ( keys %{$args{metadata}} ) {
        unless($args{access_token} and $key eq q{access_token}){
           $params{$key} = $args{metadata}{$key};
        }
    }

    my $content = build_content(\%params);
    my $headers = HTTP::Headers->new;
    $headers->header("Content-Type" => q{application/x-www-form-urlencoded});
    $headers->header("Content-Length" => bytes::length($content));
    $headers->header("Authorization" => sprintf(q{Bearer %s}, $args{access_token})) 
        if($args{access_token}); 
    my $req = HTTP::Request->new( POST => $self->{registration_endpoint}, $headers, $content );

    my $res = $self->{agent}->request($req);
    $self->{last_request}  = $req;
    $self->{last_response} = $res;

    my ($credentials, $errmsg);
    try {
        $credentials = $self->{response_parser}->parse($res, REQUIRE_REGISTRATION_ACCESS_TOKEN);
    } catch {
        $errmsg = "$_";
    };
    return $credentials || $self->error($errmsg);
}

=head2 update( %params )

execute client update
and returns L<OIDC::Lite::Client::Credential> object.

=over 4

=item access_token

Registration Access Token returned by registration request

=item metadata

Configuration parameters

=back

=cut

sub update {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        access_token    => 1,
        metadata        => { type => HASHREF },
    });
    Carp::croak "redirect_uris not found" unless (exists $args{metadata}{redirect_uris});

    my %params = (
        operation            => 'client_update',
    );
    for my $key ( keys %{$args{metadata}} ) {
        unless($key eq q{access_token}){
           $params{$key} = $args{metadata}{$key};
        }
    }

    my $content = build_content(\%params);
    my $headers = HTTP::Headers->new;
    $headers->header("Content-Type" => q{application/x-www-form-urlencoded});
    $headers->header("Content-Length" => bytes::length($content));
    $headers->header("Authorization" => sprintf(q{Bearer %s}, $args{access_token}));
    my $req = HTTP::Request->new( POST => $self->{registration_endpoint}, $headers, $content );

    my $res = $self->{agent}->request($req);
    $self->{last_request}  = $req;
    $self->{last_response} = $res;

    my ($credentials, $errmsg);
    try {
        $credentials = $self->{response_parser}->parse($res);
    } catch {
        $errmsg = "$_";
    };
    return $credentials || $self->error($errmsg);
}

=head2 rotate_secret( %params )

execute rotate secret
and returns L<OIDC::Lite::Client::Credential> object.

=over 4

=item access_token

Registration Access Token returned by registration request

=back

=cut

sub rotate_secret {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        access_token    => 1,
    });

    my %params = (
        operation            => 'rotate_secret',
    );

    my $content = build_content(\%params);
    my $headers = HTTP::Headers->new;
    $headers->header("Content-Type" => q{application/x-www-form-urlencoded});
    $headers->header("Content-Length" => bytes::length($content));
    $headers->header("Authorization" => sprintf(q{Bearer %s}, $args{access_token}));
    my $req = HTTP::Request->new( POST => $self->{registration_endpoint}, $headers, $content );

    my $res = $self->{agent}->request($req);
    $self->{last_request}  = $req;
    $self->{last_response} = $res;

    my ($credentials, $errmsg);
    try {
        $credentials = $self->{response_parser}->parse($res);
    } catch {
        $errmsg = "$_";
    };
    return $credentials || $self->error($errmsg);
}

=head2 last_request

Returns a HTTP::Request object that is used
when you obtain or refresh access token last time internally.

=head2 last_request

Returns a HTTP::Response object that is used
when you obtain or refresh access token last time internally.

=cut

sub last_request  { $_[0]->{last_request}  }
sub last_response { $_[0]->{last_response} }

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Ryo Ito

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
