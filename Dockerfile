FROM ubuntu:15.10

WORKDIR /gauntlt

ADD . . 

RUN apt-get update && \
	apt-get install -y --no-install-recommends apt-utils software-properties-common && \
	DEBIAN_FRONTEND=noninteractive apt-add-repository ppa:brightbox/ruby-ng && \
	apt-get update && apt-get install -y git ruby2.2 ruby2.2-dev build-essential libz-dev libcurl4-gnutls-dev python-software-properties libcurl4-gnutls-dev python-dev python-pip nmap bundler build-essential chrpath libssl-dev libxft-dev libfreetype6 libfreetype6-dev libfontconfig1 wget libfontconfig1-dev bundler sqlmap

RUN pip install --upgrade setuptools && \
	pip install sslyze && \
	pip install typing && \
	pip install requests && \
	pip install BeautifulSoup && \
	cd Garmr && \
	python setup.py install

RUN mv phantomjs-2.1.1-linux-x86_64 /usr/local/share && \
	ln -s /usr/local/share/phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/bin/ 

RUN	gem install gauntlt --no-ri && \
gem install -include-dependancies gauntlt --no-ri

CMD export SSLYZE_PATH=/usr/local/bin/sslyze && \
	export arachni_path=/usr/local/bin/arachni && \
	export garmr_path=/usr/local/bin/garmr && \
	export PATH=$PATH:/gauntlt/arachni/bin && \
	gauntlt
	