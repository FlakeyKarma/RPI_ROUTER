#!/bin/python3

import os,sys
CMD = str("dig +noall +answer -x %s > DNS_RESOLUTION" % (sys.argv[1]))
os.system("%s" % (CMD))

OVERWRITE = None

with open('DNS_RESOLUTION', 'r') as FIL:
	OVERWRITE = (''.join(FIL.read().split('\t')[3:]))

with open('DNS_RESOLUTION', 'w') as FIL:
	FIL.write(OVERWRITE)
