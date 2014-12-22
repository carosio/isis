AutoISIS Netconf
================

AutoISIS imeplements netconf using the netopeer-server. For netconf to work,
the netopeer-server has to be running with the correct modules loaded. The
following describes how to setup the netopeer-server and the modules for
usage with AutoISIS.

The instructions were tested on Debian 7.x (Wheezy)

#### 1) Install dependencies

    $ sudo apt-get install \
                        autoconf \
                        aufomake \
                        build-essential \
                        git-core \
                        libtool \
                        libxml2-dev \
                        libxslt1-dev \
                        openssh-server \
                        pkg-config \
                        python-libxml2 \
                        subversion \
                        xsltproc

#### 2) Install pyang

    $ svn checkout http://pyang.googlecode.com/svn/trunk/ pyang-read-only
    $ cd pyang-read-only/
    $ python setup.py build
    $ sudo python setup.py install

#### 3) Install libnetconf

    $ git clone https://code.google.com/p/libnetconf/
    $ cd libnetconf/
    $ sed -i configure.in -e '/AC_INIT/a LDFLAGS="-lrt $LDFLAGS"'
    $ autoreconf -fis
    $ ./configure \
                  --enable-debug \
                  --enable-debug-threads \
                  --disable-libssh2 \
                  --disable-url
    $ make
    $ sudo make install

#### 4) Install the netopeer server

    $ git clone https://code.google.com/p/netopeer/
    $ cd netopeer/server/
    $ ./configure \
                  --disable-dbus \
                  --enable-debug \
                  --with-sshd=/usr/sbin/sshd
    $ make
    $ sudo make install
    $ sudo touch /usr/local/etc/netopeer/cfgnetopeer/datastore.xml # Create empty datastore

#### 5) Install the ietf-routing transapi module

    $ git clone https://git.netdef.org/scm/osr/transapi-ietf-routing.git
    $ cd transapi-ietf-routing/
    $ autoreconf -fis
    $ ./configure \
                  --enable-debug
    $ make
    $ sudo make install

#### 6) Install ietf-interfaces transapi module (for ipv6 prefix config)

    $ git clone https://git.netdef.org/scm/osr/transapi-ietf-interfaces.git
    $ cd transapi-ietf-interfaces/
    $ autoreconf -fis
    $ ./configure \
                  --enable-debug
    $ make
    $ sudo make install

#### 7) Start the netconf server

    $ sudo /usr/local/bin/netopeer-server -v 2

======

As a basic netconf client to poke the server you just started, you can use the netopeer-cli:

    $ sudo apt-get install libreadline-dev
    $ cd netopeer/cli/
    $ ./configure \
                  --enable-debug
    $ make
    $ sudo make install
 
    $ netopeer-cli
    netconf> connect --login root 127.0.0.1

At that prompt you can use commands like 'get' 'get-config' 'edit-config', which perform
as described in the netconf specification.

The login for root is the same as the root login on the machine. It is imperative to
use the root account since all other accounts cannot do any configuration by default.
To change this, NACM access control roles have to be configured that permit the users
to modify the configuration.

AutoISIS Netconf Functionality
==============================

Configuration-wise, it currently supports a subset of the ietf-isis model,
allowing IS-IS autoconfig to be bootstrapped and tweaked. With the sys.config
provided in the distribution, AutoISIS will start in autoconfig mode without
any interfaces enabled. Interfaces can be enabled/disabled via netconf, an
example config looks like this:

	<routing xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
			 xmlns="urn:ietf:params:xml:ns:yang:ietf-routing"
			 xmlns:rt="urn:ietf:params:xml:ns:yang:ietf-routing"
			 nc:operation="replace">
	  <routing-instance>
		<name>default</name>
		<routing-protocols>
		  <routing-protocol xmlns:isis="urn:ietf:params:xml:ns:yang:ietf-isis">
			<type>isis:isis</type>
			<name>AutoISIS</name>
			<isis xmlns="urn:ietf:params:xml:ns:yang:ietf-isis">
			  <instance>
				<routing-instance>default</routing-instance>
				<interfaces>
				  <interface>
					<name>dummy1</name>
					<enabled>false</enabled>
					<interface-type>broadcast</interface-type>
					<priority>
					  <level>level-1</level>
					  <value>38</value>
					</priority>
					<metric>
					  <level>level-1</level>
					  <value>1000</value>
					</metric>
				  </interface>
				  <interface>
					<name>dummy2</name>
				  </interface>
				</interfaces>
			  </instance>
			</isis>
		  </routing-protocol>
		</routing-protocols>
	  </routing-instance>
	</routing>

Also, we added basic support to configure IPv6 prefixes via netconf,
a config for this looks like this:

	<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"
				xmlns:ianaift="urn:ietf:params:xml:ns:yang:iana-if-type"
				xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
				nc:operation="replace">
	  <interface>
		<name>dummy2</name>
		<type>ianaift:ethernetCsmacd</type>
		<ipv6 xmlns="urn:ietf:params:xml:ns:yang:ietf-ip">
		  <address>
			<ip>FD3B:A8D6:BEF4:70F4::5</ip>
			<prefix-length>64</prefix-length>
		  </address>
		</ipv6>
	  </interface>
	</interfaces>

This should permit to setup AutoISIS and IPv6 routing solely via netconf,
without HNCP.

For introspection, we provide the IS-IS internal status as described in the
ietf-isis model. For debugging, it can also be viewed at
`http://[...]:8080/state-netconf.yaws`
