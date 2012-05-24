package SUPL::DBusObject;

use strict;
use warnings;

use 5.014;

our $VERSION = 0.001;

use base qw(Net::DBus::Object);

=head1 NAME

SUPL::DBusObject - Base class of all SUPL DBus Objects and configuration handler

=head1 DESCRIPTION

This module manages right dbus initialisation for derived interfaces

=head1 METHODS

=cut

my %config;
my %services;

sub new
{
    my ( $class, %cfg ) = @_;
    my $service = _service(%cfg);
    my $self = $class->SUPER::new( $service, _object_path(%cfg) );

    bless( $self, $class );

    return $self;
}

sub _bus_name
{
    my %cfg = @_;
    return $cfg{'bus-name'} // $config{'bus-name'} // "org.vfnet.supl";
}

sub _service
{
    my $bus_name = _bus_name(@_);
    unless ( defined( $services{$bus_name} ) )
    {
        my $bus = Net::DBus->find();
        $services{$bus_name} = Net::DBus::Service->new( $bus, $bus_name );
    }

    return $services{$bus_name};
}

sub _object_path
{
    my %cfg = @_;
    return $cfg{'object-path'} // $config{'object-path'} // "/org/vfnet/supl";
}

sub set_default_config
{
    %config = @_;
}

1;
