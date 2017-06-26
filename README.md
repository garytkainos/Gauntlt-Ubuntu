Gauntlt Docker, based on: Ubuntu15:10

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

Roadmap

- Arachni attack expansion 
- Custom attacks


Installation 

Required Docker to be installed.

		git clone https://github.com/garytkainos/Gauntlt-Ubuntu 
		Docker Build .
		Docker run <Image ID>
