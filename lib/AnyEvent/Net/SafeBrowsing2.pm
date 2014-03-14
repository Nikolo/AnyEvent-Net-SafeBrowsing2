package AnyEvent::Net::SafeBrowsing2;

use strict;
use warnings;

use Carp;
use URI;
use Digest::SHA qw(sha256);
use List::Util qw(first);
use MIME::Base64;
use IO::Socket::SSL;
use AnyEvent::Net::SafeBrowsing2::Log;
use AnyEvent::Net::SafeBrowsing2::Storage;
use AnyEvent::Net::SafeBrowsing2::Utils;
use Mouse;
use AnyEvent::HTTP;

our $VERSION = '0.83';

=head1 NAME

AnyEvent::Net::SafeBrowsing2 - AnyEvent Perl extension for the Safe Browsing v2 API.

=head1 SYNOPSIS

  use AnyEvent;
  use AnyEvent::Net::SafeBrowsing2;
  use AnyEvent::Net::SafeBrowsing2::Tarantool;

  my $cv = AnyEvent->condvar;
  
  my $storage = AnyEvent::Net::SafeBrowsing2::Tarantool->new({
    host              => 'tarantool.host', 
	port              => '33013', 
	a_chunks_space    => 0, 
	s_chunks_space    => 1, 
	full_hashes_space => 2
  });
  $storage->dbh->connect();

  my $sb = AnyEvent::Net::SafeBrowsing2->new({
	server => "http://safebrowsing.clients.google.com/safebrowsing/", 
	key => "key";
	storage => $storage,
  });

  $sb->update(['goog-malware-shavar'], sub {warn "Next hope after ".$_[0], $cv->send()});
  $cv->recv;

TODO
  my $match = $sb->lookup(url => 'http://www.gumblar.cn/');
  
  if ($match eq MALWARE) {
	print "http://www.gumblar.cn/ is flagged as a dangerous site";
  }

  $storage->close();

=head1 DESCRIPTION

AnyEvent::Net::SafeBrowsing2 implements the Google Safe Browsing v2 API.

The library passes most of the unit tests listed in the API documentation. See the documentation (L<https://developers.google.com/safe-browsing/developers_guide_v2>) for more details about the failed tests.

The Google Safe Browsing database must be stored and managed locally. L<AnyEvent::Net::SafeBrowsing2::Tarantool> uses Tarantool as the storage back-end. Other storage mechanisms (databases, memory, etc.) can be added and used transparently with this module.
TODO
The source code is available on github at L<https://github.com/juliensobrier/Net-Google-SafeBrowsing2>.

If you do not need to inspect more than 10,000 URLs a day, you can use L<AnyEvent::Net::SafeBrowsing2::Lookup> with the Google Safe Browsing v2 Lookup API which does not require to store and maintain a local database. Use AnyEvent::Net::SafeBrowsing2::Empty for this one.

IMPORTANT: If you start with an empty database, you will need to perform several updates to retrieve all the Google Safe Browsing information. This may require up to 24 hours. This is a limitation of the Google API, not of this module.

=cut

=head1 CONSTRUCTOR

=over 4

=back

=head2 new()

Create a AnyEvent::Net::SafeBrowsing2 object

  my $sb = AnyEvent::Net::SafeBrowsing2->new(
	key 	=> "key", 
    storage	=> AnyEvent::Net::SafeBrowsing2::Tarantool->new(...),
	log     => AnyEvent::Net::SafeBrowsing2::Log->new({debug_level => 'debug3'}),
	mac		=> 0,
  );

Arguments

=over 4

=item server

Required. Safe Browsing Server.

=item mac_server

Safe Browsing MAC Server.

=item key

Required. Your Safe browsing API key

=item storage

Required. Object which handle the storage for the Safe Browsing database (AnyEvent::Net::SafeBrowsing2::Empty by default). See L<AnyEvent::Net::SafeBrowsing2::Storage> for more details.

=item mac

Optional. Set to 1 to enable Message Authentication Code (MAC). 0 (disabled) by default.

=item version

Optional. Safe Browsing version. 2.2 by default

=item log

Optional. Object for log writing. Default AnyEvent::Net::SafeBrowsing2::Log

=item data

Optional. Object which handle the storage for the additioanl params. Default AnyEvent::New::SafeBrowsing2::Data

=item data_filepath

Optional. Path to data file 

=item http_timeout 

Optional. Timeout for request to Safe Browsing service. Default 60 sec

=item user_agent

Optional. User agent which be received to SafeBrowsing service. Default AnyEvent::Net::SafeBrowsing2 client $VERSION

=item cache_time

Time for chace result of full hashes. Default 45 min

=item default_retry

Retry timeout after unknown fail. Default 30 sec

=back

=cut

has server       => (is => 'rw', isa => 'Str', required => 1 );
has mac_server   => (is => 'rw', isa => 'Str' );
has key          => (is => 'rw', isa => 'Str', required => 1 );
has version      => (is => 'rw', isa => 'Str', default => '2.2' );
has mac          => (is => 'rw', isa => 'Bool', default => 0 );
has log          => (is => 'rw', isa => 'Object', default => sub {AnyEvent::Net::SafeBrowsing2::Log->new({debug_level => 'info'})});
has storage      => (is => 'rw', isa => 'Object', default => sub {AnyEvent::Net::SafeBrowsing2::Storage->new()});
has data         => (is => 'rw', isa => 'Object');
has data_filepath=> (is => 'rw', isa => 'Str', default => '/tmp/safebrowsing_data' );
has in_update    => (is => 'rw', isa => 'Int');
has force        => (is => 'rw', isa => 'Bool', default => '0');
has http_timeout => (is => 'ro', isa => 'Int', default => '60');
has user_agent   => (is => 'rw', isa => 'Str', default => 'AnyEvent::Net::SafeBrowsing2 client '.$VERSION );
has cache_time   => (is => 'ro', isa => 'Int', default => 45*60);
has default_retry=> (is => 'ro', isa => 'Int', default => 30);
=head1 PUBLIC FUNCTIONS

=over 4

=back

=head2 update()

Perform a database update.

  $sb->update('list', sub {});

Return the time of next hope to update db

This function can handle two lists at the same time. If one of the list should not be updated, it will automatically skip it and update the other one. It is faster to update two lists at once rather than doing them one by one.

NOTE: If you start with an empty database, you will need to perform several updates to retrieve all Safe Browsing information. This may require up to 24 hours. This is a limitation of API, not of this module.

Arguments

=over 4

=item list

Required. Update a specific list.

=item callback

Required. Callback function that will be called after db is updated.

=back

=cut

sub update {
	my ($self, $list, $cb_ret) = @_;
	die "Required callback" unless $cb_ret;
	return unless $list;
	if( $self->in_update() ){
		# Already in update status next try after 30 sec 
		$cb_ret->( $self->default_retry() );
		return;
	}
	$self->in_update( scalar @$list );
	my $mwait;
	my $cb = sub {
		my ($wait) = @_;
		$mwait = $wait if !$mwait || $wait < $mwait;
		$self->in_update( $self->in_update()-1 );
		$self->log->log_debug2( "In update: ".$self->in_update() );
		$cb_ret->($mwait) unless $self->in_update();
	};
	foreach my $item ( @$list ){
		my $info = $self->data->get('updated/'.$item);
		$self->log->log_info( "Update info: ", $info );
		if(!$info || $info->{'time'} + $info->{'wait'} < AnyEvent::now() || $self->force ) {
			$self->log->log_info("OK to update $item: " . AnyEvent::now() . "/" . ($info ? $info->{'time'} +  $info->{'wait'} : 'first update'));
			my $do_request = sub {
				my($client_key, $wrapped_key) = @_;
				if ($self->mac && (!$client_key || !$wrapped_key)) {
					$self->log->log_error("MAC error ".$client_key.", ".$wrapped_key);
					$cb->($self->default_retry());
				}
				else {
					$self->storage->get_regions(list => $item, cb => sub {
						my($a_range, $s_range) = @_;
						unless( defined $a_range ){
							$self->log->log_error( 'Get range error' );
							$cb->($self->default_retry());
							return;
						}
						my $chunks_list = '';
						if ($a_range ne '') {
							$chunks_list .= "a:$a_range";
						}
						if ($s_range ne '') {
							$chunks_list .= ":" if ($a_range ne '');
							$chunks_list .= "s:$s_range";
						}
						my $body .= "$item;$chunks_list";
						$body .= ":mac" if ($self->mac);
						$body .= "\n";
						my $url = $self->server."downloads?client=api&apikey=".$self->key."&appver=$VERSION&pver=".$self->version;
						$url .= "&wrkey=$wrapped_key" if $self->mac;
				 		$self->log->log_debug1( "Url: ".$url );
				 		$self->log->log_debug1( "Body: ".$body );
						http_post( $url, $body, %{$self->param_for_http_req}, sub {
							my ($data, $headers) = @_; 
							if( $headers->{Status} == 200 ){
								if( $data ){
									$self->log->log_debug3("Response body: ".$data);
									$self->process_update_data( $data, {client_key => $client_key, wrapped_key => $wrapped_key}, $cb );
								}
								else {
									$cb->($self->default_retry());
								}
							}
							else {
								$self->log->log_error("Bad response from server ".$headers->{Status} );
								$self->update_error($item, $cb);
							}
							return;
						});
						return;
					});
				}
				return;
			};

			if( $self->mac ){
				$self->get_mac_keys( $do_request );
			}
			else {
				$do_request->();
			}
		}
		else {
			$self->log->log_info("Too early to update $item");
			$cb->(int($info->{'time'} + $info->{'wait'}-AE::now()));
		}
	}
	return;
}

=head2 force_update()

Perform a force database update.

  $sb->force_update('list', sub {});

Return the time of next hope to update db

Be careful if you call this method as too frequent updates might result in the blacklisting of your API key.

Arguments

=over 4

=item list

Required. Update a specific list.

=item callback

Required. Callback function that will be called after db is updated.

=back

=cut

sub force_update {
	my $self = shift;
	$self->force(1);
	$self->update(@_);
	$self->force(0);
	return;
}

=head2 lookup()

Lookup a URL against the Safe Browsing database.

  my $match = $sb->lookup(list => 'name', url => 'http://www.gumblar.cn', cb => sub {});

Returns the name of the list if there is any match, returns an empty string otherwise.

Arguments

=over 4

=item list

Required. Lookup against a specific list.

=item url

Required. URL to lookup.

=item callback

Required. Callback function that will be called after db is updated.

=back

=cut

sub lookup {
	my ($self, %args) 	= @_;
	my $list 			= $args{list}		|| die "List is required";
	my $url 			= $args{url}		|| die "URL is required";
	my $cb              = $args{cb}         || die "Callback is required";

	# TODO: create our own URI management for canonicalization
	# fix for http:///foo.com (3 ///)
	$url =~ s/^(https?:\/\/)\/+/$1/;

	my $uri = URI->new($url)->canonical;
	my $domain = $uri->host;
	my @hosts = $self->canonical_domain_suffixes($domain); # only top-3 in this case
	my $processed = 0;
	my $ret_matched = [];
	my $watcher = sub {
		my $match = shift;
		push @$ret_matched, $match if $match;
		$processed++;
		if( $processed == @hosts ){
			$cb->($ret_matched);
		}
	};
	foreach my $host (@hosts) {
		$self->log->log_debug1("Domain for key: $domain => $host");
		my $suffix = $self->prefix("$host/"); # Don't forget trailing hash
		$self->log->log_debug2("Host key: ".unpack( 'V', $suffix));
		$self->lookup_suffix(lists => $list, url => $url, suffix => unpack( 'V', $suffix ), cb => $watcher);
	}
	return;
}

=head1 PRIVATE FUNCTIONS

These functions are not intended to be used externally.

=over 4

=back

=head2 BUILD()

Constructor

=cut

sub BUILD {
	my $self = shift;
	$self->storage->logger($self->log);
	if( $self->data && $self->data_filepath ){
		die "Available only one parameter data or data_filepath";
	}
	$self->data( AnyEvent::New::SafeBrowsing2::Data->new( path => $self->data_filepath ));
	return $self;
}

=head2 param_for_http_req()

Generate params for http request

=cut

sub param_for_http_req {
	my $self = shift;
	return {timeout => $self->http_timeout, tls_ctx => {verify => 1}, headers => { "user-agent" => $self->user_agent }}
}

=head2 process_update_data()

Process the data received from server.

=cut

sub process_update_data {
	my ($self, $data, $keys, $cb) = @_;
	my @lines = split /\s/, $data;

	my $wait = $self->default_retry();

	my @redirections = ();
	my $del_add_duration = 0;
	my $del_sub_duration = 0;
	my $add_range_info = '';
	my $list = '';

	foreach my $line (@lines) {
		if ($line =~ /n:\s*(\d+)\s*$/) {
			$self->log->log_info("Next poll: $1 seconds");
			$wait = $1;
			$self->data->set( 'updated/'.$list, {'time' => AE::now(), 'wait' => $wait} ) if $list;
		}
		elsif ($line =~ /i:\s*(\S+)\s*$/) {
			$self->log->log_debug1("List: $1");
			$list = $1;
			$self->data->set( 'updated/'.$list, {'time' => AE::now(), 'wait' => $wait} ) if $wait;
		}
		elsif ($line =~ /m:(\S+)$/ && $self->mac) {
			my $hmac = $1;
			$self->log->log_debug3("MAC of request: $hmac");

			# Remove this line for data
			$data =~ s/^m:(\S+)//g;

			if (!AnyEvent::Net::SafeBrowsing2::Utils->validate_data_mac(data => $data, key => $keys->{client_key}, digest => $hmac, logger => $self->log) ) {
				$self->log->log_error("MAC error on main request");
				@redirections = ();
				last;
			}
		}
		elsif ($line =~ /u:\s*(\S+),(\S+)\s*$/) {
			unless( $list ){
				$self->log->log_error("Unknown list. Skip.");
				next;
			}
			$self->log->log_debug1("Redirection: $1");
			$self->log->log_debug3("MAC: $2");
			push(@redirections, [$1, $list, $2]);
		}
		elsif ($line =~ /u:\s*(\S+)\s*$/) {
			unless( $list ){
				$self->log->log_error("Unknown list. Skip.");
				next;
			}
			$self->log->log_debug1("Redirection: $1");
			push(@redirections, [$1, $list, '']);
		}
		elsif ($line =~ /ad:(\S+)$/) {
			unless( $list ){
				$self->log->log_error("Unknown list. Skip.");
				next;
			}
			$self->log->log_debug1("Delete Add Chunks: $1");

			$add_range_info = $1 . " $list";
			my $nums = AnyEvent::Net::SafeBrowsing2::Utils->expand_range($1);
			if( @$nums ){
				$self->storage->delete_add_chunks(chunknums => $nums, list => $list, cb => sub {$self->log->log_debug2(@_)});
				# Delete full hash as well
				$self->storage->delete_full_hashes(chunknums => $nums, list => $list, cb => sub {$self->log->log_debug2(@_)}) ;
			}
		}
		elsif ($line =~ /sd:(\S+)$/) {
			unless( $list ){
				$self->log->log_error("Unknown list. Skip.");
				next;
			}
			$self->log->log_debug1("Delete Sub Chunks: $1");

			my $nums = AnyEvent::Net::SafeBrowsing2::Utils->expand_range($1);
			$self->storage->delete_sub_chunks(chunknums => $nums, list => $list, cb => sub {}) if @$nums;
		}
		elsif ($line =~ /e:pleaserekey/ && $keys->{client_key}) {
			unless( $list ){
				$self->log->log_error("Unknown list. Skip.");
				next;
			}
			$self->log->log_info("MAC key has been expired");
			$self->delete_mac_keys();
			$wait = 10;
			last;
		}
		elsif ($line =~ /r:pleasereset/) {
			unless( $list ){
				$self->log->log_error("Unknown list. Skip.");
				next;
			}
			$self->log->log_info("Database must be reset");

			$self->storage->reset($list);
			@redirections = ();
			$wait = 10;
			last;
		}
	}
	my $have_error = 0;
	my $get_redir;
	$get_redir = sub {
		my $redirections = shift;
		my $data = shift( @$redirections );
		my $redirection = $data->[0];
		$list = $data->[1];
		my $hmac = $data->[2];
		$self->log->log_debug1("Url: https://$redirection");
		http_get( "https://$redirection", %{$self->param_for_http_req}, sub {
			my ($data, $headers) = @_; 
			$self->log->log_debug1("Checking redirection https://$redirection ($list)");
			if( $headers->{Status} == 200 ){
				if( $self->mac && !AnyEvent::Net::SafeBrowsing2::Utils->validate_data_mac(data => $data, key => $keys->{client_key}, digest => $hmac) ) {
					$self->log->log_error("MAC error on redirection");
					$self->log->log_debug1("Length of data: " . length($data));
					$have_error = 1;
				}
				$self->parse_data(data => $data, list => $list, cb => sub {
					my $error = shift;
					if( $error ){
						$self->log->log_error("Have error while update data");
						$self->update_error($list, $cb);
					}
					else {
						if( @$redirections ){
							$get_redir->($redirections);
						}
						else {
							$cb->($wait);
						}
					}
				});
			}
			else {
				$self->log->log_error("Request to $redirection failed ".$headers->{Status});
				$self->update_error($list, $cb);
			}
			return;
		});
	};
	if( @redirections ){
		$get_redir->(\@redirections);
	}
	else {
		$cb->($wait);
	}



=rem
	my $process_count = -1;
	my $watcher = sub {
		my $error = shift;
		$process_count++;
		$have_error ||= $error;
		$self->log->log_debug2("Watcher count: ".$process_count." <==> ".scalar( @redirections ));
		if( $process_count == scalar @redirections ){
			if( $have_error ){
				$self->log->log_error("Have error while update data");
				$self->update_error($list, $cb);
			}
			else {
				$cb->($wait);
			}	
		}
	};
	$watcher->(); # For empty @redirections
	
	foreach my $data (@redirections) {
		my $redirection = $data->[0];
		$list = $data->[1];
		my $hmac = $data->[2];
		$self->log->log_debug1("Url: https://$redirection");
		http_get( "https://$redirection", %{$self->param_for_http_req}, sub {
			my ($data, $headers) = @_; 
			$self->log->log_debug1("Checking redirection https://$redirection ($list)");
			if( $headers->{Status} == 200 ){
				#$self->log->log_debug1(substr($data->as_string, 0, 250));
				#$self->log->log_debug1(substr($data->content, 0, 250));
				if( $self->mac && !AnyEvent::Net::SafeBrowsing2::Utils->validate_data_mac(data => $data, key => $keys->{client_key}, digest => $hmac) ) {
					$self->log->log_error("MAC error on redirection");
					$self->log->log_debug1("Length of data: " . length($data));
					$have_error = 1;
				}
				$self->parse_data(data => $data, list => $list, cb => $watcher);
			}
			else {
				$self->log->log_error("Request to $redirection failed ".$headers->{Status});
				$watcher->( 1 );
			}
			return;
		});
	}
=cut
	return;
}


=head2 lookup_suffix()

Lookup a host prefix.

=cut

sub lookup_suffix {
	my ($self, %args) 	= @_;
	my $lists 			= $args{lists} 		|| croak "Missing lists";
	my $url 			= $args{url}		|| return '';
	my $suffix			= $args{suffix}		|| return '';
	my $cb              = $args{cb}         || die "Callback is required";

	# Calculcate prefixes
	my @full_hashes = $self->full_hashes($url); # Get the prefixes from the first 4 bytes
	my @full_hashes_prefix = map (substr($_, 0, 4), @full_hashes);
 	# Local lookup
	$self->local_lookup_suffix(lists => $lists, url => $url, suffix => $suffix, full_hashes_prefix => [@full_hashes_prefix], cb => sub {
		my $add_chunks = shift;
		unless( scalar @$add_chunks ){
			$cb->();
			return;
		}
		# Check against full hashes
		my $found = '';
		my $processed = 0;
		my $watcher = sub {
			my $list = shift;
			$found ||= $list if $list;  
			$processed++;
			if($processed == @$add_chunks){
				if( $found ){
					$cb->($found);
				}
				else {
					$self->log->log_debug2("No match");
					$cb->();
				}
			}
		};

		# get stored full hashes
		foreach my $add_chunk (@$add_chunks) {
			$self->storage->get_full_hashes( chunknum => $add_chunk->{chunknum}, timestamp => time() - $self->cache_time, list => $add_chunk->{list}, cb => sub {
				my $hashes = shift;
				if( @$hashes ){
					$self->log->log_debug2("Full hashes already stored for chunk " . $add_chunk->{chunknum} . ": " . scalar @$hashes);
					my $fnd = '';
					$self->log->log_debug1( "Searched hashes: ", \@full_hashes );
					foreach my $full_hash (@full_hashes) {
						foreach my $hash (@$hashes) {
							if ($hash->{hash} eq $full_hash && defined first { $hash->{list} eq $_ } @$lists) {
								$self->log->log_debug2("Full hash was found in storage: ", $hash);
								$fnd = $hash->{list};
							}
						}
					}
					$watcher->($fnd);
				}
				else {
					# ask for new hashes
					# TODO: make sure we don't keep asking for the same over and over
					$self->request_full_hash(prefixes => [ map($_->{prefix} || $_->{hostkey}, @$add_chunks) ], cb => sub {
						my $hashes = shift;
						$self->log->log_debug1( "Full hashes: ", $hashes);
						$self->storage->add_full_hashes(full_hashes => $hashes, timestamp => time(), cb => sub {});
						$processed = 0;
						$found = '';
						my $watcher = sub {
							my $list = shift;
							$found ||= $list if $list;  
							$processed++;
							if($processed == @full_hashes){
								if( $found ){
									$cb->($found);
								}
								else {
									$cb->();
								}
							}
						};
						foreach my $full_hash (@full_hashes) {
							my $hash = first { $_->{hash} eq  $full_hash} @$hashes;
							if (! defined $hash){
								$watcher->();
								next;
							}

							my $list = first { $hash->{list} eq $_ } @$lists;

							if (defined $hash && defined $list) {
								$self->log->log_debug2("Match: $full_hash");
								$watcher->($hash->{list});
							}
						}
					});
				}
			});
		}
	});
	return;
}

=head2 lookup_suffix()

Lookup a host prefix in the local database only.

=cut

sub local_lookup_suffix {
	my ($self, %args) 			= @_;
	my $lists 					= $args{lists} 				|| croak "Missing lists";
	my $url 					= $args{url}				|| return ();
	my $suffix					= $args{suffix}				|| return ();
	my $full_hashe_list 		= $args{full_hashes}		|| [];
	my $full_hashes_prefix_list = $args{full_hashes_prefix} || [];
	my $cb                      = $args{cb}                 || die "Callback is required";

	# Step 1: get all add chunks for this host key
	# Do it for all lists
	$self->storage->get_add_chunks(hostkey => $suffix, lists => $lists, cb => sub {
		my $add_chunks = shift;
		unless( scalar @$add_chunks ){
			$cb->([]); 
			return;
		}
		# Step 2: calculcate prefixes
		# Get the prefixes from the first 4 bytes
		my @full_hashes_prefix = @{$full_hashes_prefix_list};
		if (scalar @full_hashes_prefix == 0) {
			my @full_hashes = @{$full_hashe_list};
			@full_hashes = $self->full_hashes($url) if (scalar @full_hashes == 0);

			@full_hashes_prefix = map (substr($_, 0, 4), @full_hashes);
		}
		# Step 3: filter out add_chunks with prefix
		my $i = 0;
		while ($i < scalar @$add_chunks) {
			if ($add_chunks->[$i]->{prefix} ne '') {
				my $found = 0;
				foreach my $hash_prefix (@full_hashes_prefix) {
					if ( $add_chunks->[$i]->{prefix} eq $hash_prefix) {
						$found = 1;
						last;
					}
				}
				if ($found == 0) {
					$self->log->debug2("No prefix found");
					splice(@$add_chunks, $i, 1);
				}
				else {
					$i++;
				}
			}
			else {
				$i++;
			}
		}
		unless( scalar @$add_chunks ){
			$cb->([]); 
			return;
		}
		# Step 4: get all sub chunks for this host key
		$self->storage->get_sub_chunks(hostkey => $suffix, lists => $lists, cb => sub {
			my $sub_chunks = shift;
			foreach my $sub_chunk (@$sub_chunks) {
				my $i = 0;
				while ($i < scalar @$add_chunks) {
					my $add_chunk = $add_chunks->[$i];

					if ($add_chunk->{chunknum} != $sub_chunk->{addchunknum} || $add_chunk->{list} ne $sub_chunk->{list}) {
						$i++;
						next;
					}

					if ($sub_chunk->{prefix} eq $add_chunk->{prefix}) {
						splice(@$add_chunks, $i, 1);
					}
					else {
						$i++;
					}
				}
			}
			$cb->( $add_chunks ); 
		});
	});
	return ;
}

=head2 local_lookup()

Lookup a URL against the local Safe Browsing database URL. This should be used for debugging purpose only. See the lookup for normal use.

  my $match = $sb->local_lookup(url => 'http://www.gumblar.cn');

Returns the name of the list if there is any match, returns an empty string otherwise.

Arguments

=over 4

=item list

Required. Lookup against a specific list.

=item url

Required. URL to lookup.

=item callback

Required. Callback function that will be called after db is updated.

=back

=cut

sub local_lookup {
	my ($self, %args) 	= @_;
	my $list 			= $args{list}		|| '';
	my $url 			= $args{url}		|| return '';

	my @lists = @{$self->{list}};
	@lists = @{[$args{list}]} if ($list ne '');


	# TODO: create our own URI management for canonicalization
	# fix for http:///foo.com (3 ///)
	$url =~ s/^(https?:\/\/)\/+/$1/;

	my $uri = URI->new($url)->canonical;

	my $domain = $uri->host;
	
	my @hosts = $self->canonical_domain_suffixes($domain); # only top-3 in this case

	foreach my $host (@hosts) {
		$self->log->debug1("Domain for key: $domain => $host");
		my $suffix = $self->prefix("$host/"); # Don't forget trailing hash
		$self->log->debug1("Host key: $suffix");

		my @matches = $self->local_lookup_suffix(lists => [@lists], url => $url, suffix => $suffix);
		return $matches[0]->{list} . " " . $matches[0]->{chunknum}  if (scalar @matches > 0);
	}

	return '';

}

=head2 get_mac_keys()

Request the Message Authentication Code (MAC) keys

=cut

sub get_mac_keys {
	my ($self, $cb) = @_;
	my $keys = $self->data->get('mac_keys');
	if ($keys->{client_key} eq '' || $keys->{wrapped_key} eq '') {
		$self->request_mac_keys(sub{
			my ($client_key, $wrapped_key) = @_;
			$self->data->set('mac_keys', {client_key => $client_key, wrapped_key => $wrapped_key});
			$cb->($client_key, $wrapped_key);
		});
	}
	else{
		$cb->($keys->{client_key}, $keys->{wrapped_key});
	}
	return;
}

=head2 delete_mac_keys()

Request the Message Authentication Code (MAC) keys

=cut

sub delete_mac_keys {
	my ($self, $cb) = @_;
	$self->data->set('mac_keys', {});
	return;
}


=head2 request_mac_keys()

Request the Message Authentication Code (MAC) keys.

=cut

sub request_mac_keys {
	my ($self, $cb) = @_;
	my $client_key = '';
	my $wrapped_key = '';
	my $url = $self->mac_server."newkey?client=api&apikey=".$self->key."&appver=$VERSION&pver=".$self->version;
	$self->log->debug1( "Url for get keys: ".$url );
	http_get($url, %{$self->param_for_http_req}, sub {
		my ($data, $headers) = @_; 
		if( $headers->{Status} == 200 ){
			if ($data =~ s/^clientkey:(\d+)://mi) {
				my $length = $1;
				$self->log->log_debug1("MAC client key length: $length");
				$client_key = substr($data, 0, $length, '');
				$self->log->log_debug2("MAC client key: $client_key");
				substr($data, 0, 1, ''); # remove 
				if ($data =~ s/^wrappedkey:(\d+)://mi) {
					$length = $1;
					$self->log->log_debug1("MAC wrapped key length: $length");
					$wrapped_key = substr($data, 0, $length, '');
					$self->log->log_debug2("MAC wrapped key: $wrapped_key");
					$cb->(decode_base64($client_key), $wrapped_key);
				}
				else {
					$cb->('', '');
				}
			}
		}
		else {
			$self->log->log_error("Key request failed: " . $headers->{Status});
			$cb->('', '');
		}
	});
	return;
}

=head2 update_error()

Handle server errors during a database update.

=cut

sub update_error {
	my ($self, $list, $cb) = @_;

	my $info = $self->data->get('updated/'.$list);
	$info->{errors} = 0 if (! exists $info->{errors});
	my $errors = $info->{errors} + 1;
	my $wait = 0;

	$wait = $errors == 1 ? 60
		: $errors == 2 ? int(30 * 60 * (rand(1) + 1)) # 30-60 mins
	    : $errors == 3 ? int(60 * 60 * (rand(1) + 1)) # 60-120 mins
	    : $errors == 4 ? int(2 * 60 * 60 * (rand(1) + 1)) # 120-240 mins
	    : $errors == 5 ? int(4 * 60 * 60 * (rand(1) + 1)) # 240-480 mins
	    : $errors  > 5 ? 480 * 60
		: 0;

	$self->data->set('updated/'.$list, {'time' => $info->{time}||AE::now(), 'wait' => $wait, errors => $errors});
	$cb->($wait);
	return;
}

=head2 parse_s()

Parse data from a rediration (add asnd sub chunk information).

=cut

sub parse_data {
	my ($self, %args) 	= @_;
	my $data			= $args{data}		 || '';
	my $list  			= $args{list}		 || '';
	my $cb              = $args{cb}          || die "Callback is required";

	my $chunk_num = 0;
	my $hash_length = 0;
	my $chunk_length = 0;

	my $bulk_insert_a = [];
	my $bulk_insert_s = [];
=rem
	my $in_process = 0;
	my $have_error = 0;
	my $watcher = sub {
		my $err = shift;
		$in_process--;
		$have_error ||= $err;
		$self->log->log_debug2("Watcher parse: ".length( $data )."; ".$in_process);
		if(!length( $data ) && !$in_process){
			$cb->($have_error);
		}
	};
=cut
	while (length $data > 0) {
#		$in_process++;
		my $type = substr($data, 0, 2, ''); # s:34321:4:137
		if ($data  =~ /^(\d+):(\d+):(\d+)/sgi) {
			$chunk_num = $1;
			$hash_length = $2;
			$chunk_length = $3;

			# shorten data
			substr($data, 0, length($chunk_num) + length($hash_length) + length($chunk_length) + 3, '');
			my $encoded = substr($data, 0, $chunk_length, '');
			if ($type eq 's:') {
				foreach ($self->parse_s(value => $encoded, hash_length => $hash_length)){
					push @$bulk_insert_s, {chunknum => $chunk_num, chunk => $_, list => $list};
				}
				#$self->storage->add_chunks_s(chunknum => $chunk_num, chunks => [@chunks], list => $list, cb => $watcher); # Must happen all at once => not 100% sure
			}
			elsif ($type eq 'a:') {
				foreach( $self->parse_a(value => $encoded, hash_length => $hash_length)){
					push @$bulk_insert_a, {chunknum => $chunk_num, chunk => $_, list => $list}
				}
				#$self->storage->add_chunks_a(chunknum => $chunk_num, chunks => [@chunks], list => $list, cb => $watcher); # Must happen all at once => not 100% sure
			}
			else {
				$self->log->log_error("Incorrect chunk type: $type, should be a: or s:");
				$cb->(1);
				return;
			}
			$self->log->log_debug1("$type$chunk_num:$hash_length:$chunk_length OK");
		}
		else {
			$self->log->log_error("could not parse header");
#			$watcher->(1);
			$cb->(1);
			return;
		}
	}
	my $in_process = 0;
	my $have_error = 0;
	my $watcher = sub {
		my $err = shift;
		$in_process--;
		$have_error ||= $err;
		$self->log->log_debug2("Watcher parse: ".length( $data )."; ".$in_process);
		if(!$in_process){
			$cb->($have_error);
		}
	};
	$in_process++ if @$bulk_insert_s;
	$in_process++ if @$bulk_insert_a;
	$self->storage->add_chunks_s($bulk_insert_s, $watcher) if @$bulk_insert_s;
	$self->storage->add_chunks_a($bulk_insert_a, $watcher) if @$bulk_insert_a;
	return ;
}


=head2 parse_s()

Parse s chunks information for a database update.

=cut

sub parse_s {
	my ($self, %args) 	= @_;
	my $value 			= $args{value}			|| return ();
	my $hash_length 	= $args{hash_length}	|| 4;

	my @data = ();

	if( $value ){
		while (length $value > 0) {
			my $host = unpack 'V', substr($value, 0, 4, '');
			my $count = unpack 'C', substr($value, 0, 1, ''); # hex value
			if ($count == 0) { # ADDCHUNKNUM only
				my $add_chunknum = unpack 'N', substr($value, 0, 4, ''); #chunk num
				push(@data, { host => $host, add_chunknum => $add_chunknum, prefix => '' });
				$self->log->log_debug1("$host $add_chunknum");
			}
			else { # ADDCHUNKNUM + PREFIX
				for(my $i = 0; $i < $count; $i++) {
					my $add_chunknum = unpack 'N', substr($value, 0, 4, ''); # DEC
					my $prefix = unpack 'H*', substr($value, 0, $hash_length, '');
					push(@data, { host => $host, add_chunknum => $add_chunknum, prefix =>  $prefix });
					$self->log->log_debug1("$host $add_chunknum $prefix");
				}
			}
		}
	}
	else {
		push(@data, { add_chunknum => 0, host => 0, prefix => '' });
		$self->log->log_debug1("Empty packet");
	}
	return @data;
}


=head2 parse_a()

Parse a chunks information for a database update.

=cut

sub parse_a {
	my ($self, %args)  = @_;
	my $value          = $args{value}       || return ();
	my $hash_length    = $args{hash_length} || 4;

	my @data = ();

	if( $value ){
		while (length $value > 0) {
			my $host = unpack 'V', substr($value, 0, 4, '');
			my $count = unpack 'C', substr($value, 0, 1, '');
			if ($count > 0) { # ADDCHUNKNUM only
				for(my $i = 0; $i < $count; $i++) {
					my $prefix = unpack 'H*', substr($value, 0, $hash_length, '');
					push(@data, { host => $host, prefix =>  $prefix });
					$self->log->log_debug1($host." ".$prefix);
				}
			}
			else {
				push(@data, { host => $host, prefix =>  '' });
				$self->log->log_debug1($host);
			}
		}
	}
	else {
		push(@data, { host => 0, prefix => '' });
		$self->log->log_debug1("Empty packet");
	}
	return @data;
}

=head2 canonical_domain_suffixes()

Find all suffixes for a domain.

=cut

sub canonical_domain_suffixes {
	my ($self, $domain) 	= @_;
	my @domains = ();
	if ($domain =~ /^\d+\.\d+\.\d+\.\d+$/) { # loose check for IP address, should be enough
		return ($domain);
	} 
	my @parts = split/\./, $domain; # take 3 components
	if (scalar @parts >= 3) {
		@parts = splice (@parts, -3, 3);
		push(@domains, join('.', @parts));
		splice(@parts, 0, 1);
	}
	push(@domains, join('.', @parts));
	return @domains;
}


=head2 canonical_domain()

Find all canonical domains a domain.

=cut

sub canonical_domain {
	my ($self, $domain) 	= @_;
	my @domains = ($domain);
	if ($domain =~ /^\d+\.\d+\.\d+\.\d+$/) { # loose check for IP address, should be enough
		return @domains;
	} 
	my @parts = split/\./, $domain;
	splice(@parts, 0, -6); # take 5 top most compoments
	while (scalar @parts > 2) {
		shift @parts;
		push(@domains, join(".", @parts) );
	}
	return @domains;
}

=head2 canonical_path()

Find all canonical paths for a URL.

=cut

sub canonical_path {
	my ($self, $path) 	= @_;
	my @paths = ($path); # return full path
	if ($path =~ /\?/) {
		$path =~ s/\?.*$//;
		push(@paths, $path);
	}
	my @parts = split /\//, $path;
	my $previous = '';
	while (scalar @parts > 1 && scalar @paths < 6) {
		my $val = shift(@parts);
		$previous .= "$val/";

		push(@paths, $previous);
	}
	return @paths;
}

=head2 canonical()

Find all canonical URLs for a URL.

=cut

sub canonical {
	my ($self, $url) = @_;
	my @urls = ();
	my $uri = $self->canonical_uri($url);
	my @domains = $self->canonical_domain($uri->host);
	my @paths = $self->canonical_path($uri->path_query);
	foreach my $domain (@domains) {
		foreach my $path (@paths) {
			push(@urls, "$domain$path");
		}
	}
	return @urls;
}


=head2 canonical_uri()

Create a canonical URI.

NOTE: URI cannot handle all the test cases provided by Google. This method is a hack to pass most of the test. A few tests are still failing. The proper way to handle URL canonicalization according to Google would be to create a new module to handle URLs. However, I believe most real-life cases are handled correctly by this function.

=cut

sub canonical_uri {
	my ($self, $url) = @_;
	$url = AnyEvent::Net::SafeBrowsing2::Utils->trim( $url );
	while ($url =~ s/^([^?]+)[\r\t\n]/$1/sgi) { } 
	my $uri = URI->new($url)->canonical; # does not deal with directory traversing
	if (! $uri->scheme() || $uri->scheme() eq '') {
		$uri = URI->new("http://$url")->canonical;
	}
	$uri->fragment('');
	my $escape = $uri->as_string;
	while ($escape =~ s/^([a-z]+:\/\/[^?]+)\/\//$1\//sgi) { }

	# Remove empty fragment
	$escape =~ s/#$//;

	# canonial does not handle ../ 
	while($escape =~ s/([^\/])\/([^\/]+)\/\.\.([\/?].*)$/$1$3/gi) {  }
	while($escape =~ s/([^\/])\/([^\/]+)\/\.\.$/$1/gi) {  }

	# May have removed ending /
	$escape .= "/" if ($escape =~ /^[a-z]+:\/\/[^\/\?]+$/);
	$escape =~ s/^([a-z]+:\/\/[^\/]+)(\?.*)$/$1\/$2/gi;

	# other weird case if domain = digits only, try to translte it to IP address
	if ((my $domain = URI->new($escape)->host) =~/^\d+$/) {
		my @ip = unpack("C4",pack("N",$domain));
		if( scalar( grep {$_ ne "" && $_ >= 0 && $_ <= 255} @ip) == 4 ){
			$uri = URI->new($escape);
			$uri->host(join ".", @ip);
			$escape = $uri->as_string;
		}
	}

	# Try to escape the path again
	$url = $escape;
	while (($escape = URI::Escape::uri_unescape($url)) ne $escape) { # wrong for %23 -> #
		$url = $escape;
	}

	# Fix for %23 -> #
	while($escape =~ s/#/%23/sgi) { }

	# Fix over escaping
	while($escape =~ s/^([^?]+)%%(%.*)$/$1%25%25$2/sgi) { }
	while($escape =~ s/^([^?]+)%%/$1%25%25/sgi) { }

	# URI has issues with % in domains, it gets the host wrong

		# 1. fix the host
	my $exception = 0;
	while ($escape =~ /^[a-z]+:\/\/[^\/]*([^a-z0-9%_.-\/:])[^\/]*(\/.*)$/) {
		my $source = $1;
		my $target = sprintf("%02x", ord($source));
		$escape =~ s/^([a-z]+:\/\/[^\/]*)\Q$source\E/$1%\Q$target\E/;
		$exception = 1;
	}

		# 2. need to parse the path again
	if ($exception && $escape =~ /^[a-z]+:\/\/[^\/]+\/(.+)/) {
		my $source = $1;
		my $target = URI::Escape::uri_unescape($source);

		while ($target ne URI::Escape::uri_unescape($target)) {
			$target = URI::Escape::uri_unescape($target);
		}
		$escape =~ s/\/\Q$source\E/\/$target/;

		while ($escape =~ s/#/%23/sgi) { } # fragement has been removed earlier
		while ($escape =~ s/^([a-z]+:\/\/[^\/]+\/.*)%5e/$1\&/sgi) { } # not in the host name

		while ($escape =~ s/%([^0-9a-f]|.[^0-9a-f])/%25$1/sgi) { }
	}

	return URI->new($escape);
}

=head2 canonical()

Return all possible full hashes for a URL.

=cut

sub full_hashes {
	my ($self, $url) = @_;

	my @urls = $self->canonical($url);
	my @hashes = ();

	foreach my $url (@urls) {
		push(@hashes, sha256($url));
	}

	return @hashes;
}

=head2 prefix()

Return a hash prefix. The size of the prefix is set to 4 bytes.

=cut

sub prefix {
	my ($self, $string) = @_;
	return sha256($string);
}

=head2 request_full_hash()

Request full full hashes for specific prefixes from Google.

=cut

sub request_full_hash {
	my ($self, %args) 	= @_;
	my $prefixes		= $args{prefixes}; ref $prefixes eq 'ARRAY'	|| die "Arg prefixes is required and must be arrayref";
	my $cb              = $args{cb}                                 || die "Args cb is required";
	foreach( @$prefixes ){
		$_ = pack( 'V', $_);
	}
	my $size			= length $prefixes->[0];
# 	# Handle errors
	my $i = 0;
	my $errors;
	my $delay = sub {
    	my $time = shift;
		if ((time() - $errors->{timestamp}) < $time) {
			splice(@$prefixes, $i, 1);
		}
		else {
			$i++;
		}
	};
	while ($i < scalar @$prefixes) {
		my $prefix = $prefixes->[$i];

		$errors = $self->data->get('full_hash_errors/'.unpack( 'H*', $prefix));
		if (defined $errors && $errors->{errors} > 2) { # 2 errors is OK
			$errors->{errors} == 3 ? $delay->(30 * 60) # 30 minutes
		    	: $errors->{errors} == 4 ? $delay->(60 * 60) # 1 hour
		      	: $delay->(2 * 60 * 60); # 2 hours
		}
		else {
			$i++;
		}
	}

	my $url = $self->server . "gethash?client=api&apikey=" . $self->key . "&appver=$VERSION&pver=" . $self->version;
	$self->log->log_debug1( "Full hash url: ". $url);

	my $prefix_list = join('', @$prefixes);
	my $header = "$size:" . scalar @$prefixes * $size;
	my $body = $header."\n".$prefix_list;
	$self->log->log_debug1( "Full hash data: ". $body);
	http_post( $url, $body, %{$self->param_for_http_req}, sub {
		my ($data, $headers) = @_; 
		if( $headers->{Status} == 200 && length $data){
			$self->log->log_debug1("Full hash request OK");
			$self->log->log_debug3("Response body: ".$data);
			$self->data->delete('full_hash_errors/'.unpack( 'H*', $_ )) for @$prefixes;
			my @hashes = ();

			# goog-malware-shavar:22428:32HEX
			while (length $data > 0) {
				if ($data !~ /^([a-z\-]+):(\d+):(\d+)/) {
					$self->log->log_error("list not found");
					$cb->([]);
					return;
				}
				my ( $list, $chunknum, $length) = ($1, $2, $3);
				substr($data,0,length($list.":".$chunknum.":".$length."\n"),'');
				my $current = 0;
				while ($current < $length) {
					my $hash = substr($data, 0, 32, '');
					push(@hashes, { hash => $hash, chunknum => $chunknum, list => $list });

					$current += 32;
				}
			}

			$cb->(\@hashes);
		}
		else {
			$self->log->log_error("Full hash request failed ".$headers->{Status} );
			foreach my $prefix (@$prefixes) {
				my $errors = $self->data->get('full_hash_errors/'.unpack( 'H*', $prefix));
				if (defined $errors && ( $errors->{errors} >=2 || $errors->{errors} == 1 && (time() - $errors->{timestamp}) > 5 * 60)) { # 5 minutes
					$self->data->set('full_hash_errors/'.unpack( 'H*', $prefix ).'/timestamp', time()); # more complicate than this, need to check time between 2 errors
				}
			}
		}
		return;
	});
	return;
}

no Mouse;
__PACKAGE__->meta->make_immutable();
 
=head1 CHANGELOG

=over 4

=back

=head1 SEE ALSO

See L<AnyEvent::Net::SafeBrowsing2::Storage>, L<AnyEvent::Net::SafeBrowsing2::Tarantool> for information on storing and managing the Safe Browsing database.

Google Safe Browsing v2 API: L<http://code.google.com/apis/safebrowsing/developers_guide_v2.html>

Yandex Safe Browsing v2 API: L<http://api.yandex.ru/safebrowsing/>

=head1 AUTHOR

Nikolay Shulyakovskiy, E<lt>shulyakovskiy@mail.ruE<gt> or E<lt>shulyakovskiy@yandex.ruE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by Nikolay Shulyakovskiy

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;

