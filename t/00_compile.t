use strict;
use Test::More tests => 20;

BEGIN { 
    use_ok('OIDC::Lite'); 
    use_ok('OIDC::Lite::Client::Credential'); 
    use_ok('OIDC::Lite::Client::Token'); 
    use_ok('OIDC::Lite::Client::TokenResponseParser'); 
    use_ok('OIDC::Lite::Client::Registration'); 
    use_ok('OIDC::Lite::Client::RegistrationResponseParser'); 
    use_ok('OIDC::Lite::Client::WebServer'); 
    use_ok('OIDC::Lite::Model::AuthInfo'); 
    use_ok('OIDC::Lite::Model::IDToken');
    use_ok('OIDC::Lite::Server::Endpoint::Token');
    use_ok('OIDC::Lite::Server::Endpoint::Registration');
    use_ok('OIDC::Lite::Server::GrantHandlers');
    use_ok('OIDC::Lite::Server::GrantHandler::AuthorizationCode');
    use_ok('OIDC::Lite::Server::RegistrationHandler');
    use_ok('OIDC::Lite::Server::RegistrationHandler::ClientAssociate');
    use_ok('OIDC::Lite::Server::RegistrationHandler::ClientUpdate');
    use_ok('OIDC::Lite::Server::RegistrationHandler::RotateSecret');
    use_ok('OIDC::Lite::Server::RegistrationHandlers');
    use_ok('OIDC::Lite::Server::Scope');
    use_ok('OIDC::Lite::Util::JWT');
};
