use 5.005;

use ExtUtils::MakeMaker;

WriteMakefile(
	NAME => 'SMB',
	DISTNAME => 'SMB',
	dist => {
		# default CP 'ln' is buggy, it changes source file permissions
		DIST_CP => 'cp',
	},
	EXE_FILES => [ glob("bin/smb-*") ],
	VERSION_FROM => 'lib/SMB.pm',
	ABSTRACT_FROM => 'lib/SMB.pm',
	AUTHOR => 'Mikhael Goikhman <migo@freeshell.org>',
);
