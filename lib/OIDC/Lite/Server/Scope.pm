package OIDC::Lite::Server::Scope;

use strict;
use warnings;
use Data::Dumper;

sub is_openid_request{
    my ($self, $scopes) = @_;

    # scopes is array ref
    return 0 unless (ref($scopes) eq 'ARRAY');

    # if it has 'openid', return true.
    return (grep {$_ eq 'openid'} @$scopes);
};

sub to_normal_claims{
    my ($self, $scopes) = @_;

    my @claims;
    foreach my $scope (@$scopes){
        push(@claims, qw{user_id})
            if($scope eq 'openid');

        push(@claims, qw{name family_name given_name middle_name 
                         nickname preferred_username profile 
                         picture website gender birthday 
                         zoneinfo locale updated_time})
            if($scope eq 'profile');

        push(@claims, qw(email email_verified))
            if($scope eq 'email');

        push(@claims, qw{address})
            if($scope eq 'address');

        push(@claims, qw{phone_number})
            if($scope eq 'phone');
    }

    return \@claims;
};

=head1 NAME

OIDC::Lite::Server::Scope - utility class for OpenID Connect Scope

=head1 SYNOPSIS

    use OIDC::Lite::Server::Scope;
    
    # return OpenID Connect request or not
    my @scopes = ...
    if(OIDC::Lite::Server::Scope->is_openid_request(\@scopes)){
        # OpenID Connect Request
        # issue ID Token
    }else{
        # OAuth 2.0 Request
        # don't issue ID Token
    }
    
    # returned normal claims for scopes
    my $claims = OIDC::Lite::Server::Scope->to_normal_claims(\@scopes);

=head1 DESCRIPTION

This is utility class for OpenID Connect scope.

=head1 METHODS

=head2 is_openid_request( $scopes )

Returns the requested scope is for OpenID Connect or not.

=head2 allow( $req )

Returns normal claims for requested scopes.

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Ryo Ito

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
