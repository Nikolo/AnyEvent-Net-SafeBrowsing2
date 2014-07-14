package AnyEvent::Net::SafeBrowsing2::Tarantool;

use utf8;
use strict;
use Mouse;
use AnyEvent::Tarantool;
use AnyEvent::Tarantool::Cluster;

extends 'AnyEvent::Net::SafeBrowsing2::Storage';

=head1 NAME

AnyEvent::Net::SafeBrowsing2::Tarantool - Tarantool as as back-end storage for the Safe Browsing v2 database 

=head1 SYNOPSIS

AnyEvent::Net::SafeBrowsing2::Storage cannot be used directly. Instead, use a class inheriting AnyEvent::Net::SafeBrowsing2::Storage, like L<AnyEvent::Net::SafeBrowsing2::Tarantool>.


  use AnyEvent::Net::SafeBrowsing2::Tarantool;

  my $storage = AnyEvent::Net::SafeBrowsing2::Tarantool->new({host => '127.0.0.1', port => '33013', a_chunks_space => 0, s_chunks_space => 1, full_hashes_space => 2, connected_cb =>  $cb});
  ...
  $storage->close();

=head1 DESCRIPTION

This is an implementation of L<AnyEvent::Net::SafeBrowsing2::Storage> using Tarantool.

=cut


=head1 CONSTRUCTOR

=over 4

=back

=head2 new()

Create a AnyEvent::Net::SafeBrowsing2::Tarantool object

  my $storage = AnyEvent::Net::SafeBrowsing2::Tarantool->new({
      master_server      => '127.0.0.1:33013',
	  slave_server       => '127.0.0.1:34014', 
	  a_chunks_space     => 0, 
	  s_chunks_space     => 1, 
	  full_hashes_space  => 2, 
	  connected_cb       => sub {}
  });

Arguments

=over 4

=item master_server

Required. Tarantool master servers host:port

=item slave_server

Optional. Tarantool slave servers host:port

=item a_chunks_space

Required. Number of space for add chunks

=item s_chunks_space

Required. Number of space for add chunks

=item full_hashes_space

Required. Number of space for full hashes

=item connected_cb

Required. Callback CodeRef

=back

=cut

has a_chunks_space    => (is => 'rw', isa => 'Int', required => 1);
has s_chunks_space    => (is => 'rw', isa => 'Int', required => 1);
has full_hashes_space => (is => 'rw', isa => 'Int', required => 1);
has all_connected     => (is => 'ro', isa => 'CodeRef', default => sub {return sub{}});

=head1 PUBLIC FUNCTIONS

=over 4

See L<AnyEvent::Net::SafeBrowsing2::Storage> for a complete list of public functions.

=back

=cut

sub BUILD {
	my $self = shift;
	eval "use ".$self->log_class.";";
	die $@ if $@;
	my $servers = [];
	die "master_server is required" unless $self->master_server;
	foreach( split ',', $self->master_server ){
		my $srv = {master => 1};
		($srv->{host}, $srv->{port}) = split ":", $_;
		push @$servers, $srv;
	}
	foreach( split ',', $self->slave_server ){
		my $srv = {};
		($srv->{host}, $srv->{port}) = split ":", $_;
		push @$servers, $srv;
	}
	$self->dbh(AnyEvent::Tarantool::Cluster->new(
		servers => $servers,
		spaces => {
			$self->a_chunks_space() => {
				name         => 'a_chunks',
				fields       => [qw/list chunknum hostkey prefix/],
				types        => [qw/STR  NUM NUM     STR/],
				indexes      => {
					0 => {
						name => 'idx_a_uniq',
						fields => ['list', 'chunknum', 'hostkey', 'prefix'],
					},
					1 => {
						name => 'idx_a_list_num',
						fields => ['list', 'chunknum'],
					},
					2 => {
						name => 'idx_a_list_host',
						fields => ['list', 'hostkey'],
					},
				},
			},
			$self->s_chunks_space() => {
				name         => 's_chunks',
				fields       => [qw/list chunknum add_num hostkey prefix/],
				types        => [qw/STR  NUM NUM     NUM     STR/],
				indexes      => {
					0 => {
						name => 'idx_s_uniq',
						fields => ['list', 'chunknum', 'hostkey', 'prefix'],
					},
					1 => {
						name => 'idx_s_list_num',
						fields => ['list', 'chunknum'],
					},
					2 => {
						name => 'idx_s_list_host',
						fields => ['list', 'hostkey'],
					},
				},
			},
			$self->full_hashes_space() => {
				name         => 'full_hashes',
				fields       => [qw/list chunknum hash timestamp/],
				types        => [qw/STR  NUM STR  NUM/],
				indexes      => {
					0 => {
						name => 'idx_s_uniq',
						fields => ['list', 'chunknum', 'hash'],
					},
					1 => {
						name => 'idx_s_list_num',
						fields => ['list', 'chunknum'],
					},
				}
			},
		},
		all_connected => $self->all_connected,
	));
	return $self;
}

sub get_regions {
	my ($self, %args) = @_;
	my $list          = $args{list}                          || die "list arg is required";
	my $cb            = $args{cb}; ref $args{'cb'} eq 'CODE' || die "cb arg is required and must be CODEREF";
	$self->dbh->master->lua( 'get_regions', [$self->a_chunks_space(), $self->s_chunks_space(), $list], {in => 'ppp', out => 'p'}, sub {
		my ($data, $error) = @_;
		if( $error ){
			log_error( 'Tarantool error: '.$error );
			$cb->();
		}
		else {
			if( $data->{tuples}->[0]->[0] && $data->{tuples}->[0]->[0] ne ';' ){
				my ($ret_a, $ret_s) = ('','');
				($ret_a, $ret_s) = split(';', $data->{tuples}->[0]->[0]);
				$cb->($ret_a, $ret_s);
			}
			else {
				$cb->('','');
			}
		}
		return;
	});
	return;
}

sub delete_add_chunks {
	my ($self, %args) = @_;
	my $chunknums     = $args{chunknums}                         || die "chunknums arg is required";
	my $list          = $args{'list'}                            || die "list arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' || die "cb arg is required and must be CODEREF";
	$self->dbh->master->lua( 'del_chunks_a', [$self->a_chunks_space(),JSON::XS->new->encode([map +{list => $list, chunknum => $_}, @$chunknums])], {in => 'pp', out => 'p'}, sub {
		my ($result, $error) = @_;
		log_error( "Tarantool error: ",$error ) if $error;
		$cb->($error ? 1 : 0);
	});
	return;
}

sub delete_sub_chunks {
	my ($self, %args) = @_;
	my $chunknums     = $args{chunknums}                         || die "chunknums arg is required";
	my $list          = $args{'list'}                            || die "list arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' || die "cb arg is required and must be CODEREF";
	$self->dbh->master->lua( 'del_chunks_s', [$self->s_chunks_space(),JSON::XS->new->encode([map +{list => $list, chunknum => $_}, @$chunknums])], {in => 'pp', out => 'p'}, sub {
		my ($result, $error) = @_;
		log_error( "Tarantool error: ",$error ) if $error;
		$cb->($error ? 1 : 0);
	});
	return;
}

sub get_add_chunks {
	my ($self, %args) = @_;
	my $hostkey       = $args{hostkey}                           || die "hostkey arg is required";
	my $list          = $args{'lists'}                           || die "lists arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' || die "cb arg is required and must be CODEREF";
	$self->dbh->slave->select('a_chunks', [map [$_,$hostkey], @$list], {index => 2}, sub{
		my ($result, $error) = @_;
		if( $error || !$result->{count} ){
			log_error( "Tarantool error: ".$error ) if $error;
			$cb->([]);
		}
		else {
			my $space = $self->dbh->master->{spaces}->{a_chunks};
			my $ret = [];
			foreach my $tup ( @{$result->{tuples}} ){
				push @$ret, {map {$_->{name} => $tup->[$_->{no}]||''} @{$space->{fields}}}
			}
			$cb->($ret); 
		}
	});
	return;
}

sub get_sub_chunks {
	my ($self, %args) = @_;
	my $hostkey       = $args{hostkey}                           || die "hostkey arg is required";
	my $list          = $args{'lists'}                           || die "lists arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' || die "cb arg is required and must be CODEREF";
	$self->dbh->slave->select('s_chunks', [map [$_,$hostkey], @$list], {index => 2}, sub{
		my ($result, $error) = @_;
		if( $error || !$result->{count} ){
			log_error( "Tarantool error: ".$error ) if $error;
			$cb->([]);
		}
		else {
			my $space = $self->dbh->master->{spaces}->{s_chunks};
			my $ret = [];
			foreach my $tup ( @{$result->{tuples}} ){
				push @$ret, {map {$_->{name} => $tup->[$_->{no}]||''} @{$space->{fields}}}
			}
			$cb->($ret); 
		}
	});
	return;
}

sub delete_full_hashes {
	my ($self, %args) = @_;
	my $chunknums     = $args{chunknums}                         || die "chunknums arg is required";
	my $list          = $args{'list'}                            || die "list arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' || die "cb arg is required and must be CODEREF";
	$self->dbh->master->lua( 'del_full_hash', [$self->full_hashes_space(),JSON::XS->new->encode([map +{list => $list, chunknum => $_}, @$chunknums])], {in => 'pp', out => 'p'}, sub {
		my ($result, $error) = @_;
		log_error( "Tarantool error: ",$error ) if $error;
		$cb->($error ? 1 : 0);
	});
	return;
}

sub get_full_hashes {
	my ($self, %args) = @_;
	my $chunknum      = $args{chunknum}                          || die "chunknum arg is required";
	my $list          = $args{'list'}                            || die "lists arg is required";
	my $timestamp     = $args{'timestamp'}                       || die "timestamp arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' || die "cb arg is required and must be CODEREF";
	$self->dbh->slave->select('full_hashes', [[$list,$chunknum]], {index => 1}, sub{
		my ($result, $error) = @_;
		if( $error || !$result->{count} ){
			log_error( "Tarantool error: ".$error ) if $error;
			$cb->([]);
		}
		else {
			my $space = $self->dbh->master->{spaces}->{full_hashes};
			my $ret = [];
			foreach my $tup ( @{$result->{tuples}} ){
				if( $tup->[$space->{fast}->{timestamp}->{no}] < $timestamp ){
					$self->dbh->master->delete('full_hashes', [$tup->[0], $tup->[1], $tup->[2]], sub {
						my ($result, $error) = @_;
						log_error( "Tarantool error: ".$error ) if $error;
					});
				}
				else {
					push @$ret, {map {$_->{name} => $tup->[$_->{no}]||''} @{$space->{fields}}}
				}
			}
			$cb->($ret); 
		}
	});
	return;
}

sub add_chunks_s {
	my ($self, $chunks, $cb) = @_;
	ref $cb eq 'CODE' || die "cb arg is required and must be CODEREF";
	$self->dbh->master->lua( 'add_chunks_s', [$self->s_chunks_space(),JSON::XS->new->encode($chunks)], {in => 'pp', out => 'p'}, sub {
		my ($result, $error) = @_;
		log_error( "Tarantool error: ",$error ) if $error;
		$cb->($error ? 1 : 0);
	});
}

sub add_chunks_a {
	my ($self, $chunks, $cb) = @_;
	ref $cb eq 'CODE' || die "cb arg is required and must be CODEREF";
	$self->dbh->master->lua( 'add_chunks_a', [$self->a_chunks_space(),JSON::XS->new->encode($chunks)], {in => 'pp', out => 'p'}, sub {
		my ($result, $error) = @_;
		log_error( "Tarantool error: ", $error ) if $error;
		$cb->($error ? 1 : 0);
	});
}

sub add_full_hashes {
	my ($self, %args) 	= @_;
	my $full_hashes   = $args{full_hashes}                       || die "full_hashes arg is required";
	my $timestamp     = $args{timestamp}                         || die "timestamp arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' || die "cb arg is required and must be CODEREF";

	my $inserted = 0;
	my $err = 0;
	foreach my $fhash (@$full_hashes) {
		$self->dbh->master->insert('full_hashes', [$fhash->{list}, $fhash->{chunknum}, $fhash->{hash}, $timestamp], sub {
			my ($result, $error) = @_;
			log_error( "Tarantool error: ".$error ) if $error;
			$inserted++;
			$err ||= $error;
			if( $inserted == @$full_hashes ){
				$cb->($err ? 1 : 0);
			}
		});
	}
	return;
}


no Mouse;
__PACKAGE__->meta->make_immutable();

=head1 SEE ALSO

See L<AnyEvent::Net::SafeBrowsing2> for handling Safe Browsing v2.

See L<AnyEvent::Net::SafeBrowsing2::Storage> for the list of public functions.

Google Safe Browsing v2 API: L<http://code.google.com/apis/safebrowsing/developers_guide_v2.html>

=head1 AUTHOR

Nikolay Shulyakovskiy, E<lt>shulyakovskiy@mail.ruE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by Nikolay Shulyakovskiy

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut

1;

