package Net::Radio::Location::SUPL::DBusObject::Translator;

use strict;
use warnings;

use 5.010;

=head1 NAME

Net::Radio::Location::SUPL::DBusObject::Translator - DBus Server Object to receive messages to translate

=head1 DESCRIPTION

=head1 METHODS

=cut

our $VERSION = 0.001;

use Net::Radio::Location::SUPL::XS;

use base qw(Net::Radio::Location::SUPL::DBusObject);
use Net::DBus::Exporter qw(org.ofono.supl.Translator);

use Log::Any qw($log);

=head2 new

Instantiates new SUPL PDU Translator Object to the D-Bus service provided.

The configuration parameters for instantiating are described at
L<Net::Radio::Location::SUPL::DBusObject/new|Net::Radio::Location::SUPL::DBusObject::new>.

=cut

sub new
{
    my ( $class, %cfg ) = @_;
    my $self = $class->SUPER::new(%cfg);

    bless( $self, $class );

    Net::Radio::Location::SUPL::MainLoop->add($self);

    $log->debugf( "%s initialized and added to MainLoop control", __PACKAGE__ );

    return $self;
}

=head2 SuplPduStringToXmlString

Receives an encoded SUPL PDU as string via D-Bus message and returns the
decoded XML representation of the PDU.

=cut

dbus_method( "SuplPduStringToXmlString", ["string"], ["string"] );

sub SuplPduStringToXmlString
{
    my ( $self, $enc_pdu ) = @_;
    my $supl_xml = Net::Radio::Location::SUPL::XS::ulp_pdu_to_xml($enc_pdu);
    return $supl_xml;
}

=head2 SuplPduArrayToXmlString

Receives an encoded SUPL PDU as array of bytes via D-Bus message and returns
the decoded XML representation of the PDU.

=cut

dbus_method( "SuplPduArrayToXmlString", [ [ "array", "byte" ] ], ["string"] );

sub SuplPduArrayToXmlString
{
    my ( $self, $pdu ) = @_;
    my $pdu_str = join( "", map { chr($_) } @$pdu );
    return $self->SuplPduStringToXmlString($pdu_str);
}

=head2 SuplPduHexStringToXmlString

Receives an encoded SUPL PDU as hexdump string via D-Bus message and returns
the decoded XML representation of the PDU.

=cut

dbus_method( "SuplPduHexStringToXmlString", ["string"], ["string"] );

sub SuplPduHexStringToXmlString
{
    my ( $self, $pdu ) = @_;
    my $pdu_str = pack( "H*", $pdu );
    return $self->SuplPduStringToXmlString($pdu_str);
}

=head1 AUTHOR

Jens Rehsack, C<< <rehsack at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-supl-test at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=SUPL-Test>.
I will be notified, and then you'll automatically be notified of progress
on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::Radio::Location::SUPL::Test

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=SUPL-Test>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/SUPL-Test>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/SUPL-Test>

=item * Search CPAN

L<http://search.cpan.org/dist/SUPL-Test/>

=back

=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 Jens Rehsack.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

1;
