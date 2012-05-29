#!perl -T

use Test::More tests => 6;

BEGIN {
    use_ok( 'SUPL::XS' ) || print "Bail out on SUPL::XS!\n";
    use_ok( 'SUPL::Test' ) || print "Bail out on SUPL::Test!\n";
    use_ok( 'SUPL::DBusObject' ) || print "Bail out on SUPL::DBusObject!\n";
    use_ok( 'SUPL::DBusObject::RecvPushMsg' ) || print "Bail out on SUPL::DBusObject::RecvPushMsg!\n";
    use_ok( 'SUPL::DBusObject::Translator' ) || print "Bail out on SUPL::DBusObject::Translator!\n";
    use_ok( 'SUPL::MainLoop' ) || print "Bail out on SUPL::MainLoop!\n";
}

diag( "Testing SUPL::Test $SUPL::Test::VERSION, Perl $], $^X" );
