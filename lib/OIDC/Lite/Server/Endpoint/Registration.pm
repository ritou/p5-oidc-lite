package OIDC::Lite::Server::Endpoint::Registration;

use strict;
use warnings;

use overload
    q(&{})   => sub { shift->psgi_app },
    fallback => 1;

use Plack::Request;
use Try::Tiny;
use Params::Validate;

use OAuth::Lite2::Server::Context;
use OAuth::Lite2::Formatters;
use OAuth::Lite2::Server::Error;
use OIDC::Lite::Server::Error;
use OIDC::Lite::Server::RegistrationHandlers;

sub new {
    my $class = shift;
    my %args = Params::Validate::validate(@_, {
        data_handler => 1,
        error_uri    => { optional => 1 },
    });
    my $self = bless {
        data_handler   => $args{data_handler},
        error_uri      => $args{error_uri},
        registration_handlers => {},
    }, $class;
    return $self;
}

sub support_type {
    my ($self, $type) = @_;
    my $handler = OIDC::Lite::Server::RegistrationHandlers->get_handler($type)
        or OIDC::Lite::Server::Error::InvalidType->throw;
    $self->{registration_handlers}{$type} = $handler;
}

sub support_types {
    my $self = shift;
    $self->support_type($_) for @_;
}

sub data_handler {
    my ($self, $handler) = @_;
    $self->{data_handler} = $handler if $handler;
    $self->{data_handler};
}

sub psgi_app {
    my $self = shift;
    return $self->{psgi_app}
        ||= $self->compile_psgi_app;
}

sub compile_psgi_app {
    my $self = shift;

    my $method;
    my $app = sub {
        my $env = shift;
        my $res;
        my $req = Plack::Request->new($env);
        if ($env->{REQUEST_METHOD} eq "POST") {
            try {
                $res = $self->handle_request($req);
            } catch {
                # Internal Server Error
                warn $_;
                $res = $req->new_response(500);
            };
        }else{
            $res = $req->new_response(404);
        }
        return $res->finalize;
    };

    return $app;
}

sub handle_request {
    my ($self, $request) = @_;

    my $formatter = OAuth::Lite2::Formatters->get_formatter_by_name("json");
    my $res = try {

        my $operation = $request->param("operation")
            or OIDC::Lite::Server::Error::InvalidOperation->throw(
                description => q{The value of operation is not found},
            );

        my $handler = $self->{registration_handlers}{$operation}
            or OIDC::Lite::Server::Error::InvalidOperation->throw(
                description => q{The value of operation is invalid or not supported},
            );

        my $data_handler = $self->{data_handler}->new(request => $request);
        my $result = $handler->handle_request($data_handler);

        # success response
        return $request->new_response(200,
            [ "Content-Type"  => $formatter->type,
              "Cache-Control" => "no-store"  ],
            [ $formatter->format($result) ]);

    } catch {

        if ($_->isa("OAuth::Lite2::Server::Error")) {

            my $error_params = { error => $_->type };
            $error_params->{error_description} = $_->description
                if $_->description;
            $error_params->{error_uri} = $self->{error_uri}
                if $self->{error_uri};

            return $request->new_response($_->code,
                [ "Content-Type"  => $formatter->type,
                  "Cache-Control" => "no-store"  ],
                [ $formatter->format($error_params) ]);

        } else {

            die $_;

        }

    };
}

=head1 NAME

OIDC::Lite::Server::Endpoint::Registration - registration endpoint PSGI application

=head1 SYNOPSIS

registration_endpoint.psgi

    use strict;
    use warnings;
    use Plack::Builder;
    use OIDC::Lite::Server::Endpoint::Registration;
    use MyDataHandlerClass;

    builder {
        my $app = OIDC::Lite::Server::Endpoint::Registration->new(
            data_handler => 'MyDataHandlerClass',
        );
        $app->support_types(qw(client_register client_update rotate_secret));
        $app;
    };

=head1 DESCRIPTION

The object of this class behaves as PSGI application (subroutine reference).
This is for OpenID Connect registration-endpoint.

Reference spec:
http://openid.net/specs/openid-connect-registration-1_0-14.html

At first you have to make your custom class inheriting L<OIDC::Lite::Server::DataHandler>,
and setup PSGI file with it.

=head1 METHODS

=head2 new( %params )

=over 4

=item data_handler

name of your custom class that inherits L<OIDC::Lite::Server::DataHandler>
and implements interface.

=item error_uri

Optional. URI that represents error description page.
This would be included in error responses.

=back

=head2 support_grant_type( $type )

=head2 support_grant_types( @types )

You can set 'client_register', 'rotate_secret', or 'client_update'

=head2 data_handler

=head2 psgi_app

=head2 compile_psgi_app

=head2 handle_request( $req )

=head1 TEST

You can test with L<OAuth::Lite2::Agent::PSGIMock> and some of client classes.

    my $app = OIDC::Lite::Server::Endpoint::Registration->new(
        data_handler => 'MyDataHandlerClass',
    );

    my $mock_agent = OAuth::Lite2::Agent::PSGIMock->new(app => $app);
    my $client = OAuth::Lite2::Client::Registration->new(
        registration_endpoint   => q{http://localhost/redirect}
        agent   => $mock_agent,
    );

    my $config = {
        redirect_uris => q{https://example.com/redirect_uri},
        application_name => q{test_app_name},
    };

    my $client_credentials = $client->associate(
        metadata => $config,
    );
    ok($client_credentials);

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Ryo Ito

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
