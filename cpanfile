requires 'Class::Accessor::Fast', '0.34';
requires 'JSON::XS';
requires 'JSON::WebToken', '0.10';
requires 'Crypt::OpenSSL::RSA';
requires 'MIME::Base64', '3.11';
requires 'OAuth::Lite2', '0.10';
requires 'Params::Validate', '0.95';
requires 'perl', '5.008001';

on build => sub {
    requires 'ExtUtils::MakeMaker', '6.62';
    requires 'Test::More';
    requires 'Test::MockObject';
};
