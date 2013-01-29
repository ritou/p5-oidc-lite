package OIDC::Lite::Server::Error;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::Error';
use overload
    q{""}    => sub { sprintf q{%s: %s}, $_[0]->type, $_[0]->description },
    fallback => 1;

=head1 NAME

OIDC::Lite::Server::Error - OpenID Connect server errors (for Dynamic Client Registration)

=head1 SYNOPSIS

    # At registration-endpoint

    try {


    } catch {

        if ($_->isa("OAuth::Lite2::Server::Error")) {

            my %error_params = ( error => $_->type );
            $error_params{error_description} = $_->description if $_->description;
            $error_params{scope} = $_->scope if $_->scope;

            $req->new_response($_->code,
                [ "Content-Type" => $formatter->type, "Cache-Control" => "no-store" ],
                [ $formatter->format(\%error_params) ],
            );

        } else {

            # rethrow
            die $_;

        }

    };

=head1 DESCRIPTION

OAuth 2.0 error classes.

See
L<http://openid.net/specs/openid-connect-registration-1_0-12.html#anchor7>,

=head1 METHODS

=head1 ERRORS

=over 4

=item OIDC::Lite::Server::Error::InvalidOperation

=item OIDC::Lite::Server::Error::InvalidClientId

=item OIDC::Lite::Server::Error::InvalidClientSecret

=item OIDC::Lite::Server::Error::InvalidRedirectUri

=item OIDC::Lite::Server::Error::InvalidConfigurationParameter

=back

=cut

sub new {
    my ($class, %args) = @_;
    bless {
        description => $args{description} || '',
        state       => $args{state}       || '',
        code        => $args{code}        || 400,
    }, $class;
}

sub throw {
    my ($class, %args) = @_;
    die $class->new(%args);
}

sub code        { $_[0]->{code}         }
sub type        { die "abstract method" }
sub description { $_[0]->{description}  }
sub state       { $_[0]->{state}        }

# OpenID Connect Server Error
package OIDC::Lite::Server::Error::InvalidOperation;
our @ISA = qw(OIDC::Lite::Server::Error);
sub code { 400 }
sub type { "invalid_operation" }

package OIDC::Lite::Server::Error::InvalidClientId;
our @ISA = qw(OIDC::Lite::Server::Error);
sub code { 400 }
sub type { "invalid_client_id" }

package OIDC::Lite::Server::Error::InvalidClientSecret;
our @ISA = qw(OIDC::Lite::Server::Error);
sub code { 400 }
sub type { "invalid_client_secret" }

package OIDC::Lite::Server::Error::InvalidRedirectUri;
our @ISA = qw(OIDC::Lite::Server::Error);
sub code { 400 }
sub type { "invalid_redirect_uri" }

package OIDC::Lite::Server::Error::InvalidConfigurationParameter;
our @ISA = qw(OIDC::Lite::Server::Error);
sub code { 400 }
sub type { "invalid_configuration_parameter" }

package OIDC::Lite::Server::Error;

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
