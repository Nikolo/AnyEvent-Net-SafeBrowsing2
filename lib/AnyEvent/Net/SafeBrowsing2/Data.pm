package AnyEvent::Net::SafeBrowsing2::Data;

use strict;
use utf8;
use Mouse;
use YAML;

=head1 NAME

AnyEvent::Net::SafeBrowsing2::Data - File storage object for any data 

=head1 SYNOPSIS

  use AnyEvent::Net::SafeBrowsing2::Data;

  my $data = AnyEvent::Net::SafeBrowsing2::Data->new({path => '/tmp/datafile'});
  ...
  $data->get();
  $data->set();

=head1 DESCRIPTION

File storage for any data, like Config YAML forrmat

=cut


=head1 CONSTRUCTOR

=over 4

=back

=head2 new()

Create a AnyEvent::Net::SafeBrowsing2::Tarantool object

  my $storage = AnyEvent::Net::SafeBrowsing2::Tarantool->new({
      path => '/tmp/datafile',
  });

Arguments

=over 4

=item path

Required. Path to file

=back

=cut

has path   => (is => 'ro', isa => 'Str', required => 1);
has config => (is => 'ro', isa =>'Hash', default => sub {return {updated => {}, mac_keys => {client_key => '', wrapped_key => ''}, full_hash_errors => {}}});

sub BUILD {
	my $self = shift;
	if( ! -f $self->path ){
		if(open(my $FILE,">",$self->path)){
			YAML::DumpFile($self->path, $self->config);
		}
		else {
			die "Can't write to config file";
		}
	}
	else {
		$self->config(YAML::LoadFile($self->path));
	}
	return;
}

sub get {
	my $self = shift;
	my $prop = shift;
	my $value = $self->config;
	foreach my $part (split '/', $prop){
		$value = eval {$value->{$part}};
		if($@){
			die "Can't access $prop. $@"
		}
	}
	return $value; 
}

sub set {
	my $self = shift;
	my $prop = shift;
	my $val = shift;
	if( $prop =~ m{^(.*)/([^/]*)$} ){
		$self->get($1)->{$2} = $vaue;
	}
	else {
		$self->config->{$prop} = $value;
	}
	YAML::DumpFile($self->path, $self->config);
	return $prop;
}

no Mouse;
__PACKAGE->meta->make_imutable();

