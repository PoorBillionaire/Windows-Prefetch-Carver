Windows-Prefetch-Carver
========================    
Python script to carve Windows Prefetch artifacts from arbitrary binary data

Description
-------------
The Windows application prefetch mechanism is in place to offer performance benefits when launching applications. It's also one of the more beneficial forensic artifacts regarding evidence of applicaiton execution. prefetch-carve.py provides functionality for carving prefetch artifacts from binary data - such as unallocated disk space, raw memory images, etc. prefetch-carve.py will output to the specified file, and supports multiple output formats.

Supported Prefetch Types
--------------------------
Windows 10 Prefetch files are compressed, and are unable to be carved from disk in this manner. All other Prefetch formats are supported (Windows XP - Windows 8.1)

Command-Line Options
---------------------

::

    optional arguments:
      -h, --help            show this help message and exit
      -f FILE, --file FILE  Carve Prefetch files from the given file
      -o OUTFILE, --outfile OUTFILE
                            Write results to the given file
      -c, --csv             Output results in csv format
      -m, --mactime         Output results in mactime format
      -t, --tln             Output results in tln format
      -s SYSTEM, --system SYSTEM
                            System name (use with -t)

Testing
--------
Thorough teseting is still underway. I plan to integrate this project with Travis CI shortly.


Installation 
--------------
Using setup.py:

::
    
    python setup.py install
    
Using pip:

::
    
    pip install prefetchcarve
