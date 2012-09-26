use strict;
use Test::More tests => 10;

BEGIN { 
    use_ok('OIDC::Lite'); 
    use_ok('OIDC::Lite::Client::Token'); 
    use_ok('OIDC::Lite::Client::TokenResponseParser'); 
    use_ok('OIDC::Lite::Client::WebServer'); 
    use_ok('OIDC::Lite::Model::AuthInfo'); 
    use_ok('OIDC::Lite::Model::IDToken');
    use_ok('OIDC::Lite::Server::Endpoint::Token');
    use_ok('OIDC::Lite::Server::GrantHandler::AuthorizationCode');
    use_ok('OIDC::Lite::Server::GrantHandlers');
    use_ok('OIDC::Lite::Util::JWT');
};
