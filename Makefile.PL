use strict;
use warnings;

use inc::Module::Install;

name 'OIDC-Lite';
all_from 'lib/OIDC/Lite.pm';

requires(
    'Params::Validate'      => 0.95,
    'Class::Accessor::Fast' => 0.34,
    'Data::Dump'            => 1.17,
    'OAuth::Lite2'          => 0.03,
    'JSON::WebToken'        => 0.05,
);

tests('t/*.t t/*/*.t t/*/*/*.t');

#author_tests('xt');
test_requires(
    'Test::More' => 0,
    #    'Test::Class' => 0,
);

auto_include;
WriteAll;
