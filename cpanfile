requires 'Class::Accessor::Fast', '0.34';
requires 'Data::Dump', '1.17';
requires 'JSON';
requires 'JSON::WebToken', '0.07';
requires 'OAuth::Lite2', '0.03';
requires 'Params::Validate', '0.95';
requires 'perl', '5.008001';

on build => sub {
    requires 'Crypt::OpenSSL::RSA';
    requires 'ExtUtils::MakeMaker', '6.62';
    requires 'Test::Mock::LWP::Conditional';
    requires 'Test::More';
};
