use 5.010;
use strict;
use warnings;

use lib 'inc';
use Config;

use MyBuilder;

my $builder = MyBuilder->new(
   module_name         => 'SUPL::Test',
   license             => 'perl',
   dist_author         => q{Jens Rehsack <rehsack@cpan.org>},
   dist_version_from   => 'lib/SUPL/Test.pm',
   build_requires      => {
                           'ExtUtils::CBuilder'   => '0.27',
                           'ExtUtils::ParseXS'    => 0,
                           'Test::More'           => '0.90',
                          },
   configure_requires  => {
                           'Module::Build'        => '0.38',
                          },
   requires            => {
                           'perl' => 5.010,
			   'Config::Any' => 0,
			   'Digest::SHA' => 0,
			   'File::ConfigDir' => '0.003',
			   'Net::DBus' => '1.0.0',
                          },
   add_to_cleanup      => [
                           '*.o',
                           'asn1/*.dylib',
                           'asn1/*.so',
                           'asn1/*.dll',
                           'asn1/*.o',
                           'ULP_PDU-*'
                          ],
);

$builder->create_build_script;

