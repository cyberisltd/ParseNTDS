ParseNTDS
=========

* Author: geoff.jones@cyberis.co.uk
* Copyright: Cyberis Limited 2013
* License: GPLv3 (See LICENSE)

Small script to parse the output of NTDSExtract (Perl).

Usage
-----
Full usage instructions can be found here - http://blog.cyberis.co.uk/2012/06/password-audit-of-domain-controller.html

```
./parseNTDS.pl -f [--lmonly Only display accounts with LM passwords] [-group   <GROUP NAME>]... [--removedisabled Remove disabled accounts] [--removedlocked <LOCK COUNT>] [--showhistory Include historic passwords]
```
Example:
```
./parseNTDS.pl -f ntds.dit.output --lmonly --group 'Domain Admin' --group 'Enterprise Admin' --removedisabled --removedlocked 3 
```

Depenendicies
-------------
* Outpout from NTDSXtract
* Perl module Getopt::Long

Issues
------
Kindly report all issues via https://github.com/cyberisltd/ParseNTDS/issues
