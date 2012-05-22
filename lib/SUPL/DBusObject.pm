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

# my $services

sub new
{
    my ($class, %cfg) = @_;
    my $service = _service(%cfg);
    my $self = $class->SUPER::new($service, _bus_name(%cfg));

    bless( $self, $class );

    return $self;
}

sub _bus_name
{
    my %cfg = @_;
    return $cfg{'bus-name'} // $config{'bus-name'} // "org.ofono.supl";
}

sub _service
{
    my $bus = Net::DBus->find();
    my $service = Net::DBus::Service->new($bus, _bus_name(@_));

    return $service;
}

sub _object_path
{
    my %cfg = @_;
    return $cfg{'object-path'} // $config{'object-path'} // "/org/ofono/supl";
}

sub set_default_config
{
    %config = @_;
}

1;
