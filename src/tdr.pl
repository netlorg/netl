#!/usr/bin/perl -w
##@(#)Copyright, 1996, Regents of University of California
##@(#)portions are (c) 1997 Graham THE Ollis
##==============================================================================
## test driver (tdr.pl)
## this program runs the given file and reports on
## how it worked out.  makes .ao (actual output) and
## compares it to .eo (expected output)
##
## History:
## Date       Author	Commented
## ----       ------	---------
## 20 May 96  G. Ollis	started & finished code
## 22 May 96  G. Ollis	added support for the ERR files
##			also made the code look nice
## 23 May 96  G. Ollis	added some command line options
##			-i for interactive
##			-v to include warnings
##			-s to display the signal sent to the test program
## 24 May 96  G. Ollis  trap the no command line arguments thing
##			check to see if the program is executable
## 29 May 96  G. Ollis  treat each argument as a command
##			rather than whole line is a cmdline
## 30 May 96  G. Ollis	one line output mode
## 3  Jun 96  G. Ollis	changed local() to my()
## 12 Jun 96  G. Ollis	changed $log back to local()
##			added accounting for the data
##			append to log file unless using the
##			fixed the code!  (it works this time)
## 2  Aug 96  G. Ollis	fixed a few little things, added documentation.
## 27 Feb 97  G. Ollis	return non zero if a difference is found.
##			added return value checking.
##			all the bases are covered in glue now, carefull you
##			don't fall down.
## 8  Oct 98  G. Ollis	added -n option to display passed/total stats after
##			testing
## 25 Jun 99  G. Ollis	once again, removed the documentation from here on a
##			whim into the netl dist.  this way i can use my new
##			rms format instead of the anoying POD format.
## 04 Jul 99  G. Ollis	added diffRET file.  it's kinda silly, but is better
##			than special casing it.
##==============================================================================
## see man page for more information.  (or POD below)

require 5;		# this funny thing doesn't even do anything but is a
			# great visual aid for the version impaired.

## GLOBALS
$VERSION	= '1.00';  if($VERSION) {}
$LOG_FILE_NAME	= 'tdr.log';		# where to put the test driver log
$DATE_CMD	= 'date | cut -c5-';	# date command

## options stuff
$interactive = 0;	# (-i) by default to non-interactive
$verbose = 0;		# (-v) by default don't print out warnings
$overWrite = 0;		# (-o) by default, DO NOT overwrite log file
$disp_stats = 0;	# (-n) by default do not print out handy stats
			# and only print out if a test case fails!

$return_value = 0;	# this is the value which will be returned
			# assuming it is a "normal" execution.

$0 =~ s!^.*/!!g;

unless(defined($ARGV[0])) {
	print STDERR "usage: $0 [-v  [-i] ] [-o] [-n] cmd [args]\n";
	exit 2;
}

while($ARGV[0] =~ /^-/) {
	$arg = shift(@ARGV);
	$interactive = 1 if($arg eq '-i');
	$verbose = 1 if($arg eq '-v');
	$overWrite = 1 if($arg eq '-o');
	$disp_stats = 1 if($arg eq '-n');
}

if((-e $LOG_FILE_NAME) and ($overWrite == 0)) {
	open(LOG,">>$LOG_FILE_NAME");
} else {
	open(LOG,">$LOG_FILE_NAME");
}

$total_work = 0;
$total = 0;
$total_na = 0;
for(@ARGV) {
	&testProgram($_);
}

if($disp_stats) {
	$percent = int($total_work / $total * 100);
	if($total == $total_work) {
		print "all $total tests passed\n";
	} elsif($total_na == 0) {
		print "$total_work/$total tests passed (${percent}%)\n";
		print $total - $total_work, " tests failed\n";
	} else {
		$total -= $total_na;
		print "$total_work/$total tests passed (${percent}%)\n";
		print $total - $total_work, " tests failed\n";
		print "no expected output for $total_na tests\n";
	}
}

exit $return_value;

##==============================================================================
## testProgram
## test the given program, make the right files
##
## INPUT : program name
## OUTPUT : debuging fles
##==============================================================================

#void
sub testProgram { # $progName
	$progName = $_[0];

	$total++;

	## if the name given doesn't have the .t extension, add it unless
	## there isn't a file without a .t extension the user wants to use.
	$progName .= ".t" unless(-x $progName);

	## if the file given or file.t doesn't exist, then tell the user
	## that he's going to have to do better.
	unless(-x $progName) {
		print "file doesn't exist, or permission denied.\n";
		exit 3;
	}

	## all the file names are given here relative to the command given to tdr
	my $root;	($root = $progName) =~ s!\.t$!!;
	my $fileName = "$root.ao";
	my $errName = "$root.aERR";
	my $oldFileName = "$root.eo";
	my $oldErrName = "$root.eERR";
	my $diffFileName = "$root.diff";
	my $diffErrName = "$root.diffERR";
	my $retName = "$root.aRET";
	my $oldRetName = "$root.eRET";
	my $diffRetName = "$root.diffRET";

	## warn the user that a file is to be overwriten
	&checkFile($fileName);
	&checkFile($errName);
	&checkFile($retName);

	## run the program, redirect as needed
	system "./$progName 1> $fileName 2> $errName";

	my $exitValue = ($? >> 8);
	my $signalValue = ($? & 255);
	# right shift 8 bits - the wonders of perl.  2 values in 16 bit int
	# $exitValue is the value returned by the program
	# $signalValue is the signal used to terminate it

	## save the return value for completeness
	open(RETURN, ">$retName") || die "could not open $retName for writing $!\n";
	print RETURN "exit($exitValue) signal($signalValue)\n";
	close RETURN;

	## if there is expected output warn of differences
	my $outDiff = &checkDiff($fileName, $oldFileName, $diffFileName);
	my $errDiff = &checkDiff($errName, $oldErrName, $diffErrName);
	my $retDiff = &checkDiff($retName, $oldRetName, $diffRetName);

	local $log;		# don't tell anyone i used a local here...

	if(($outDiff==2) or ($errDiff==2) or ($retDiff==2)) {	# diff FAILED!
		$log = "diff FAILED\n";    
	} elsif(($outDiff==3) or ($errDiff==3)) {		# no expected output
		$log = "N/A\n";
		$total_na++;

	} elsif(($outDiff==0) and ($errDiff==0) and 
				 (($retDiff==3) or ($retDiff==0)) ) {
		if($disp_stats) {
			$log = "OK\r";
		} else {
			$log = "OK\n";
		}
		$total_work++;
	} else {
		$log = '';
		$log .= 'STDOUT ' if $outDiff == 1;
		$log .= 'STDERR ' if $errDiff == 1;
		$log .= 'RETVAL ' if $retDiff == 1;
		$log .= "fail\n";
		$return_value = 4;
	}
	 
	write;
#	write LOG;

format STDOUT =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$progName,	$log
.

format LOG =
@<<<<<<<<<<<<<<<<<<<<<<< : @<<<<<<<<<<<<<< @*
&getTime,		    $progName,	    $log
.

}

##==============================================================================
## getTime
## get the time for logging purposes
##
## INPUT : none
## OUTPUT : the time/date fully qualified as a string
##==============================================================================

#string
sub getTime { # void
	my($fred);

	chop($fred = `$DATE_CMD`);

	$fred;
}

##==============================================================================
## checkDiff
## this function actually checks the difference between the two files given
## and put those differences in a .diff file
##
## INPUT : expected, actual, and diff file names
## OUTPUT : exit value of diff
##==============================================================================

#int
sub checkDiff { # $actualFileName, $expetedFileName, $diffFileName

	my($fileName, $oldFileName, $diffFileName) = @_;
	my $exitValue = 3;
	my $cmd = "diff $fileName $oldFileName";
	$cmd .= " 1> $diffFileName" if defined $diffFileName;

	if(-e $oldFileName) {  # if the expected output file exists, then....
		&checkFile($diffFileName);
		system $cmd;
		$exitValue = $? >> 8;
		unlink $fileName if $exitValue == 0;
		unlink $diffFileName if defined $diffFileName;
	}
	$exitValue;	# 0 = no difference
		# 1 = difference
		# 2 = diff failed
		# 3 = no expected output
}

##==============================================================================
## checkFile
## this function checks to see if the file can be over writen.
##
## INPUT : filename
## OUTPUT : none
##==============================================================================

#void 
sub checkFile { # $fileName
	my $fileName = $_[0];
	my $inp;

	return if defined $fileName and $fileName eq '/dev/null';

	return if($verbose == 0);
	if(-e $fileName) {
		print STDERR "warning, $fileName exists, ";
		if($interactive == 1) {
			print STDERR "overwrite? ";
			$inp = <STDIN>;
			exit 1 if($inp =~ /^n/);
		}
		print STDERR "overwriting.\n" if($interactive == 0);
	}
}

