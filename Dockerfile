FROM ubuntu:15.10

WORKDIR /gauntlt

ADD . .

RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

RUN apt-get update && \
	apt-get install -y --no-install-recommends apt-utils software-properties-common && \
	DEBIAN_FRONTEND=noninteractive apt-add-repository ppa:brightbox/ruby-ng && \
	DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y libffi6 libffi-dev git ruby2.2 ruby2.2-dev build-essential libz-dev libcurl4-gnutls-dev python-software-properties libcurl4-gnutls-dev python-dev python-pip nmap bundler build-essential chrpath libssl-dev libxft-dev libfreetype6 libfreetype6-dev libfontconfig1 wget libfontconfig1-dev bundler sqlmap

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

RUN rm -rf /var/lib/gems/2.2.0/gems/gauntlt-1.0.12/lib/gauntlt/attack_aliases/arachni.json && \
	cp Arachni-Custom.json /var/lib/gems/2.2.0/gems/gauntlt-1.0.12/lib/gauntlt/attack_aliases/arachni.json 

RUN tar -xvf /gauntlt/dirb222.tar.gz &&  \
	chmod 755 /gauntlt/dirb222/configure && \
	cd /gauntlt/dirb222 && \
	sh configure && \
	make 

RUN touch /gauntlt/arachni/system/arachni-ui-web/tmp

CMD export SSLYZE_PATH=/usr/local/bin/sslyze && \
	export garmr_path=/usr/local/bin/garmr && \
	export PATH=$PATH:/gauntlt/arachni/bin && \
	export PATH=$PATH:/gauntlt/dirb222 && \
	export DIRB_WORDLISTS=/gauntlt/dirb222/wordlists && \
	gauntlt

CMD export SITE=NOTHING && \
	sed -i -e 's/$SITE/'"$SITE"'/' nmap-ports.attack
