#include <stdio.h>
#include "netl/version.h"

int
main(int argc, char *argv[])
{
        FILE *fp;

        fp = fopen("netlcc.sh", "w");
        if(fp == NULL) {
                fprintf(stderr, "hrm.  i could not open netlcc.sh for writing.");
                return 1;
        }

	fprintf(fp, "#!/bin/sh
# @(#)netlcc.sh (c) 1999 Graham THE Ollis
#===============================================================================
# front end for the netl c compiler.  this program will generate c code given
# a netl .conf file, then it will involk gcc to compile it.
#
#   Copyright (C) 1997 Graham THE Ollis <ollisg@netl.org>
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

# this is the obsecure sh version of netlcc.  wheee.

netl='%s/sbin/netl'
netl_opts=\"-v- --generate-c\"

gcc='%s'
gcc_opts=\"-I%s\"

install_dir='%s/filt'

tmp_dir='/tmp/.netl'
mkdir $tmp_dir >& /dev/null

target=0
list=''
rest=''
mods=''
while test \"$1\" != \"\"; do
	arg=$1
	shift

	case $arg in
		*.conf)
			base=`echo \"$arg\" | sed 's/\\.conf$//'`
			if $netl $netl_opts --file $arg --output-name $tmp_dir/$base.c ; then
				true
			else
				echo \"netl failed generating $base.c from $arg\"
				exit 1
			fi
			list=\"$list $base\"
		;;
		*.c)
			mods=\"$mods $arg\"
		;;
		*)
			case $arg in
				-[cSE])
					target=1
				;;
				-generate-c)
					no_gcc=1
				;;
				-install)
					do_install=1
				;;
				--version)
					echo \"netlcc version %d.%02d(sh)\"
					$gcc --version
					exit
				;;
			esac
			rest=\"$rest $arg\"
		;;
	esac
done

if test \"$no_gcc\" = 1 ; then
	for x in $list ; do
		cp $tmp_dir/$x.c .
		rm -f $tmp_dir/$x.c
	done
	exit
fi

for x in $mods ; do
	base=`echo \"$x\" | sed 's/\\.c$//'`
	fred=''
	if test \"$target\" = \"0\" ; then
		fred=\"-shared -o $base.so\"
	fi
	$gcc $gcc_opts $rest $fred $x
done

for x in $list ; do
	base=\"$x\"
	fred=''
	if test \"$target\" = \"0\" ; then
		fred=\"-shared -o $base.so\"
	fi
	$gcc $gcc_opts $rest $fred $tmp_dir/$x.c
done

if test \"$do_install\" = \"1\" ; then
	echo \"install capability has been removed.  please install by hand\"
fi

	", NETL_LIB_PATH, NETL_CC, NETL_INCLUDEPATH, NETL_LIB_PATH,
	   NETL_VER_MAJOR, NETL_VER_MINOR);

	fclose(fp);
	return 0;
}
