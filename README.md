Gauntlt Docker, based on: Ubuntu15:10

Blog post - https://www.kainos.com/closer-look-gauntlt/ 

Raw data of Docker container to allow easy customisation for each unique environment. Solution in Docker container to make it easier to integrated into the CI/CD pipeline

Configured for the following tools:

- NMAP
- SQLMAP
- Garmr
- SSLyze
- Arachni (with Phantomjs2.1.1)

Custom Arachni attacks have been added these include the following:

- Form Upload Checks
- Mixed Resource
- Insecure Cookies
- Allowed methods
- Session fixation

Requires Attack Files - You can either add them pre-build or post (or both) depending on requirments.

See example attack files - https://github.com/gauntlt/gauntlt/tree/master/examples

Installation 

Required Docker to be installed.

		git clone https://github.com/garytkainos/Gauntlt-Ubuntu 
		Docker build .
		Docker run <Image ID>
