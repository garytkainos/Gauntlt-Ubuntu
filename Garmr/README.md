# Garmr

Garmr is a tool to inspect the responses from websites for basic security requirements.

Garmr includes a set of core test cases implemented in corechecks that are derived from
the [Mozilla Secure Coding Guidelines](https://wiki.mozilla.org/WebAppSec/Secure_Coding_Guidelines)

## Installation

This version of Garmr requires Requests > 0.8.3

    git clone https://github.com/freddyb/Garmr.git
    cd Garmr
    sudo python setup.py install
    garmr -u http://my.target.app

## Usage
    usage: Runs a set of tests against the set of provided URLs
       [-h] [-u TARGETS] [-f TARGET_FILES] [-S] [-m MODULES] [-D] [-p] [-d]
       [-r REPORT] [-o OUTPUT] [-c OPTS] [-e EXCLUSIONS] [--save DUMP_PATH]

    optional arguments:
      -h, --help            show this help message and exit
      -u TARGETS, --url TARGETS
                            Add a target to test
      -f TARGET_FILES, --target-file TARGET_FILES
                            File with URLs to test
      -S, --new-sessions    Create new Session for each test
      -m MODULES, --module MODULES
                            Load an extension module
      -D, --disable-core    Disable corechecks
      -p, --force-passive   Force passives to be run for each active test
      -d, --dns             Skip DNS resolution when registering a target
      -r REPORT, --report REPORT
                            Load a reporter e.g. -r reporter.AntXmlReporter
      -o OUTPUT, --output OUTPUT
                            Default output is garmr-results.xml
      -c OPTS, --check OPTS
                            Set a parameter for a check (check:opt=value)
      -e EXCLUSIONS, --exclude EXCLUSIONS
                            Prevent a check from being run/processed
      --save DUMP_PATH      Write out a configuration file based on parameters
                            (won't run scan)
    
    
    A TARGET is an http or https scheme url to execute tests against.
     e.g. garmr -u http://localhost
    
    A MODULE is the name of a module; resolving this path needs to be improved
     e.g. garmr -m djangochecks (Experimental)
    
    An OPTS field contains the path and name of the option to set
     e.g. garmr -m webchecks -c webchecks.RobotsTest:save_contents=True
    
    A REPORT is the namespace qualified name of a reporter object or a valid alias (xml is the only current valid alias, and the default)
     e.g. garmr -r xml
    
    An EXCLUSION prevents a check from being executed
     e.g. garmr -e WebTouch
     
    Disable core checks will prevent all of the checks in corechecks from being loaded; this is useful to limit the scope of testing.

## Tasks
See [Issues on Github](https://github.com/freddyb/garmr/issues)
 
 
