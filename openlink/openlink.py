import sys
import os 
from os.path import expanduser

home = expanduser("~")

fpath=".sharedurls"
with open(home+os.sep+"sharedurls_path.txt") as f:
	fpath = f.read().strip()

with open(fpath,"w+") as f:
	if sys.argv[1] == "--":
		f.write(sys.argv[2])
	else:
		f.write(sys.argv[1])
#raw_input()