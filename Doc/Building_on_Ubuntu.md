Compiling and Installing ISIS daemon on Ubuntu 14.04LTS
=======================================================
<hr>

Installing require packages
---------------------------

### Install build environment
	sudo apt-get install git make gcc autoconf automake libtool \
		libreadline-dev texinfo sudo

### Install Erlang 16b3
	sudo apt-get install erlang erlang-base-hipe
(Only Erlang Version 16b3 supported at this time, no version 17. Ubuntu 14.04 
includes 16b3  at the time when this was written, so it should work as long as 
the package is not updated to version 17

<br><hr>

Building Dependencies
---------------------

### Rebar
(NetDEF mirror copy of Github rebar git: https://git.netdef.org/scm/mirror/github-rebar.git )

	git clone https://github.com/rebar/rebar.git rebar
	cd rebar
	git checkout a467abb
	./bootstrap
	sudo cp rebar /usr/local/bin/
	cd ..

(rebar build directory can be deleted at this point - it's no longer needed)


### Relx
(NetDEF mirror copy of Github relx git: https://git.netdef.org/scm/mirror/github-rebar.git )

	git clone https://github.com/erlware/relx.git relx

	cd relx
	git checkout 1d7f26d
	make
	sudo cp relx /usr/local/bin/
	cd ..
	
(relx build directory can be deleted at this point - it's no longer needed)

### Procket
(we use a slightly modified version of procket for this code)

	git clone https://git.netdef.org/scm/osr/procket.git procket

	cd procket
	git checkout 4d511c8
	make
	sudo cp priv/procket /usr/local/bin/
	cd ..
	
(procket build directory can be deleted at this point - it's no longer needed)
	
### Quagga (SrcDest Flavour)
Quagga needs to be compiled with the --enable-tcp-zebra option for the ISIS code (and it needs to be a version new enough to support Src-Dest routing)
		
	git clone https://git.netdef.org/scm/osr/srcdest.git quagga

	cd quagga
	./update-autotools
	./configure --enable-vtysh  --enable-user=root --enable-multipath=0 \
		--enable-tcp-zebra --prefix=/usr/local/quagga
	make
	sudo make install
	cd ..
	sudo ln -s /usr/local/quagga/bin/vtysh /usr/local/bin/vtysh
	sudo touch /usr/local/quagga/etc/zebra.conf
	sudo useradd quagga

<br><hr>
	
Building ISIS
-------------
(assuming this isis git repository was checked out to a isis directory)

	cd isis
	rebar get-deps
	rebar compile
	relx
	sudo cp -a _rel/isis /usr/local/isis
	sudo chown -R root.root /usr/local/isis

<br><hr>

Running ISIS
------------

1. Start Zebra

		sudo /usr/local/quagga/sbin/zebra -d

2. Start ISIS in background (after Zebra is running)

		sudo /usr/local/isis/bin/isis start

For further startup options and configuration commands, please refer to isis_command.md documentation file
