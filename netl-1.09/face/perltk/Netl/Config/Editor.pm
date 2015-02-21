package Netl::Config::Editor;

use Tk;
use Netl::Config::Parser;
use Netl::UI;

sub collect_errors {
	my $str = shift;
	push @error_list, "$str on line $Netl::Config::Parser::line_number";
}

sub new {
	my $mw = shift;
	my $filename = shift;
	my $input = shift;
	$input .= "\n";

	my $main = $mw->DialogBox(
				-title => "Configuration Editor",
				-buttons => ["Save", "Dismiss"],
			);
	#$main->title('Configuration Editor');
	#$main->raise($mw);

	@Netl::Config::Parser::rules = ();
	undef $Netl::Config::Parser::libdir;
	undef $Netl::Config::Parser::dumpdir;
	undef $Netl::Config::Parser::listenport;
	undef $Netl::Config::Parser::detect;
	%Netl::Config::Parser::alias = ();
	
	@error_list = ();
	eval 'Netl::Config::Parser::gparse($input, \&collect_errors)';
	if($#error_list != -1) {
		Netl::UI::toss_error_p($main, $filename, @error_list);
	}
	if($@) {
		Netl::UI::toss_error_p($main, $filename, "parser barfed",
					split("\n", $@));
	}

	my @rules = @Netl::Config::Parser::rules;
	my $libdir = $Netl::Config::Parser::libdir || '';
	my $dumpdir = $Netl::Config::Parser::dumpdir || '';
	my $listenport = $Netl::Config::Parser::listenport;
	my $detect = $Netl::Config::Parser::detect || 0;
	my %alias = $Netl::Config::Parser::alias;

	my $nb = $main->add('NoteBook', 
			'-ipadx' => 6,
			'-ipady' => 6);

	########################################################################
	# general
	########################################################################

	my $tmp = $nb->add('general', '-label' => 'General', '-underline' => 0);

	$cfgfile = '/etc/tknetl.conf';
	$tmp->LabEntry(
		'-label' => 'Config file', 
		'-labelPack' => [ '-side' => 'left', '-anchor' => 'w', ],
		'-labelWidth' => 15,
		'-width' => 50,
		'-textvariable' => \$cfgfile,
	)->pack('-side' => 'top', '-anchor' => 'nw');

	$tmp->LabEntry(
		'-label' => 'Library directory', 
		'-labelPack' => [ '-side' => 'left', '-anchor' => 'w', ],
		'-labelWidth' => 15,
		'-width' => 50,
		'-textvariable' => \$libdir,
	)->pack('-side' => 'top', '-anchor' => 'nw');

	$tmp->LabEntry(
		'-label' => 'Dump directory', 
		'-labelPack' => ['-side' => 'left', '-anchor' => 'w' ],
		'-labelWidth' => 15,
		'-width' => 50,
		'-textvariable' => \$dumpdir,
	)->pack(-side => "top", -anchor => "nw");

	########################################################################
	# raw
	########################################################################

	$tmp = $nb->add('raw', '-label' => 'raw', '-underline' => 0);
	widgets_all($tmp);

	########################################################################
	# IP
	########################################################################

	$tmp = $nb->add('ip', '-label' => 'IP', '-underline' => 0);
	widgets_all($tmp);
	widgets_ip($tmp);

	########################################################################
	# TCP
	########################################################################

	$tmp = $nb->add('tcp', '-label' => 'TCP', '-underline' => 0);
	widgets_all($tmp);
	widgets_ip_ports($tmp);

	########################################################################
	# UDP
	########################################################################

	$tmp = $nb->add('udp', '-label' => 'UDP', '-underline' => 0);
	widgets_all($tmp);
	widgets_ip_ports($tmp);

	########################################################################
	# ICMP
	########################################################################

	$tmp = $nb->add('icmp', '-label' => 'ICMP', '-underline' => 1);
	widgets_all($tmp);
	widgets_ip($tmp);

	########################################################################
	# finish off
	########################################################################

	$nb->pack(-expand => "yes",
		 -fill => "both",
		 -padx => 5, -pady => 5,
		 -side => "top");
	$main->Show
}

sub widgets_all {
	my $f = shift;
	$f->Scrolled(
		'Listbox',
		'-scrollbars'		=> 'e',
		'-width'		=> 60,
		'-height'		=> 5,
		'-selectmode'		=> 'single',
	)->pack('-side' => 'top');

	$brow = $f->Frame->pack('side' => 'top');
	$brow->Button(
		'-text'         => 'new',
		'-command'      => sub { },
		'-width'        => 10,
	)->pack('-side'         => 'left');
	$brow->Button(
		'-text'         => 'remove',
		'-command'      => sub { },
		'-width'        => 10,
	)->pack('-side'         => 'left');
	$brow->Button(
		'-text'         => 'up',
		'-command'      => sub { },
		'-width'        => 5,
	)->pack('-side'         => 'left');
	$brow->Button(
		'-text'         => 'down',
		'-command'      => sub { },
		'-width'        => 5,
	)->pack('-side'         => 'left');

	opt_lab_entry($f, 'name');
	$f2 = $f->Frame->pack('-side' => 'top');
	$f2->Label('-text' => 'hw', '-width' => 5)->pack('-side' => 'left',
						 '-anchor' => 'nw');
	$f2->Checkbutton->pack('-side' => 'left');
	$f2->Entry('-width' => 29)->pack('-side' => 'left');
	$f2->Label('-text' => '=>')->pack('-side' => 'left');
	$f2->Checkbutton->pack('-side' => 'left');
	$f2->Entry('-width' => 29)->pack('-side' => 'left');
}

sub widgets_ip {
	my $f = shift;
	my $f2 = $f->Frame->pack('-side' => 'top');
	$f2->Label('-text' => 'ip', '-width' => 6)->pack('-side' => 'left',
						 '-anchor' => 'nw');
	$f2->Checkbutton->pack('-side' => 'left');
	$f2->Entry('-width' => 29)->pack('-side' => 'left');
	$f2->Label('-text' => '=>')->pack('-side' => 'left');
	$f2->Checkbutton->pack('-side' => 'left');
	$f2->Entry('-width' => 29)->pack('-side' => 'left');
}

sub widgets_ip_ports {
	my $f = shift;
	my $f2 = $f->Frame->pack('-side' => 'top');

	$f2->Label('-text' => 'ip', '-width' => 6)->pack('-side' => 'left',
						 '-anchor' => 'nw');
	$f2->Checkbutton->pack('-side' => 'left');
	$f2->Entry('-width' => 20)->pack('-side' => 'left');
	$f2->Label('-text' => ':')->pack('-side' => 'left');
	$f2->Entry('-width' => 7)->pack('-side' => 'left');
	$f2->Label('-text' => '=>')->pack('-side' => 'left');
	$f2->Checkbutton->pack('-side' => 'left');
	$f2->Entry('-width' => 20)->pack('-side' => 'left');
	$f2->Label('-text' => ':')->pack('-side' => 'left');
	$f2->Entry('-width' => 7)->pack('-side' => 'left');
}

sub opt_lab_entry {
	my $f = shift;
	my $label = shift;
	my $f2 = $f->Frame->pack('-side' => 'top',
				 '-anchor' => 'nw');
	$f2->Label('-text' => $label, '-width' => 6)->pack('-side' => 'left');
	$f2->Checkbutton->pack('-side' => 'left');
	$f2->Entry('-width' => 60)->pack('-side' => 'left');
}

1;
