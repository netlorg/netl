#===============================================================================
#
#   Copyright (C) 1999 Graham THE Ollis <ollisg@wwa.com>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#===============================================================================

package Netl::UI;

use integer;
use Tk;
use Netl;

sub loop {
	MainLoop();
}

sub quit {
	&{$Netl::UI::onexit} if defined $Netl::UI::onexit;
	exit;
}

sub toss_info_p {
	my $mw = shift;
	my $main = $mw->Toplevel;
	$main->title('info');
	#print "----- info -----\n";
	for(@_) {
		$main->Label('-text' => $_)->grid;
		#print "$_\n";
	}
	#print "----- ----- -----\n";
	$main->Button(	'-text' => 'ok',
			'-command' => sub { $main->destroy; },
	)->grid;
}

sub toss_info {
	my $main = MainWindow->new;
	$main->title('info');
	#print "----- info -----\n";
	for(@_) {
		$main->Label('-text' => $_)->grid;
		#print "$_\n";
	}
	#print "----- ----- -----\n";
	$main->Button(	'-text' => 'ok',
			'-command' => sub { $main->destroy; },
	)->grid;
}

sub toss_error {
	my $main = MainWindow->new;
	$main->title('error');
	#print "----- error -----\n";
	for(@_) {
		$main->Label('-text' => $_)->grid;
		#print "$_\n";
	}
	#print "----- ----- -----\n";
	$main->Button(	'-text' => 'ok',
			'-command' => sub { $main->destroy; },
	)->grid;
}

sub toss_error_p {
	my $mw = shift;
	my $main = $mw->Toplevel;
	$main->title('error');
	$main->Label(
			'-bitmap' => 'error',
			'-padx' => '100', '-pady' => '100',
		)->pack('-side' => 'left');
	my $rest = $main->Frame->pack;
	for(@_) {
		$rest->Label('-text' => $_)->grid;
	}
	$rest->Button(	'-text' => 'ok',
			'-command' => sub { $main->destroy; },
	)->grid;
}

sub save_as {
	my($filename, $data) = @_;
	my $mw = MainWindow->new;
	$mw->title("save as");
	my $f = $mw->Frame->grid;
	$f->Label('-text' => 'enter filename')->grid;
	$f->Entry('-textvariable' => \$filename)->grid;
	$f = $mw->Frame->grid;
	$f->Button('-text' => 'Ok',
		'-command' => sub {
				unless(open(FP, ">$filename")) {
					toss_error('unable to open',
						$filename, "$!");
				}
				print FP $data;
				close FP;
				$mw->destroy;
			}
	)->grid($f->Button('-text' => 'Cancel',
			'-command' => sub { $mw->destroy }),
		'-stick'	=> 'nsew',
	);
}

1;
