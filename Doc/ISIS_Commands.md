Erlang ISIS commands Cheat Sheet
================================

Compile
-------
*(see README.md for pre-requisites and specific detailed instructions for Ubuntu)*

	rebar get-deps
	rebar compile
	relx

<br><hr>

Starting ISIS
-------------
### Start in background

	cd isis/_rel/isis/bin
	isis start
	
or if installed to /usr/local/isis as outlined in Install doc

	cd /usr/local/isis/bin
	isis start

### Attach to Console to background process

	isis attach

### Start in foreground

	isis console

### To reload a module you’ve just compiled with ‘rebar compile’

	l(isis_cli).

### Stop / start ISIS without exit 
(with configuration reset)

	application:stop(isis).
	application:start(isis).

<br><hr>

Startup configuration
---------------------
Startup configuration is done as required for ISIS autoconf.

Configuration is in __sys.config__ in the releases/0.0.1/ directory
(for the compiled/installed version) and src/sys.config before the compilation

The example configuration below configures ISIS for autoconf and excludes interfaces eth0.1 from ISIS

####Example configuration:
	%% Set the appropriate options for ISIS. This is copied into place by
	%% relx
	[{isis,
	  [{startup, [
			  {ignore_interfaces, ["eth0.1"]},
			  {allowed_interfaces, []},
			  {autoconf_fingerprint, <<1,2,3,4,0:256>>},
			  {autoconf, true}
			 ]}
	  ]},
	 {lager, [{handlers,
		   [
			{lager_console_backend, info},	
			{lager_file_backend, [{file, "debug.log"}, {level, debug},
					  {size, 10000000}, {date, "$D0"}, {count, 5}]},
			{lager_file_backend, [{file, "error.log"}, {level, error},
					  {size, 10000000}, {date, "$D0"}, {count, 5}]},
			{lager_file_backend, [{file, "console.log"}, {level, info},
					  {size, 10000000}, {date, "$D0"}, {count, 5}]}
		   ]},
		  {colored, true}
		 ]
	 }
	].

<br><hr>

Web Interface
-------------
### http://<host>:8080/
Shows a graphical picture of the topology together with some of the routes

### http://<host>:8080/lspdb.yaws
Shows the current (live updated) status of the lspdb database

<br><hr>
	
Essential commands
------------------

### Show Interfaces

	isis_cli:show_interfaces().

### Examine the LSP database

	isis_cli:show_database().

and

	isis_cli:show_database_detail().


### Show ISIS System ID and configured areas:

	isis_cli:show_isis().

### Show ISIS Adjacencies

	isis_cli:show_adjacencies(level_1).

or

	isis_cli:show_adjacencies(level_2).

### Show ISIS routes

	isis_cli:show_routes(level_1).

or

	isis_cli:show_routes(level_2).
		
### Set ISIS System ID

	isis_system:set_system_id(<<1,2,3,4,5,6>>).

### Set ISIS hostname 

	isis_system:set_hostname(“spangly”).

### Set ISIS encryption on interface (plain text only supported)

	isis_system:set_interface("eth1", level_1,
          [{encryption, text, <<"isis-autoconf">>}]).

### Disable ISIS encryption on interface 

	isis_system:set_interface("eth1", level_1,
          [{encryption, none, <<>>}]).

### Add ISIS Area

	isis_system:add_area(<<0:(13*8)>>),

### Remove ISIS Area

	isis_system:del_area(<<...>>).

### Turn on Interface for ISIS

	isis_system:add_interface('eth1').

### Turn on ISIS level on interface (do both if both level are required)

	isis_system:enable_level("eth1", level_1).
	isis_system:enable_level("eth1", level_2).

### Turn off ISIS level on interface (do both if both level are required)

	isis_system:disable_level("eth1", level_1).
	isis_system:disable_level("eth1", level_2).

### Dump current (running) configuration
THis returns the full configuration as currently in use (in syntax as needed to configure the isis)

	isis_system:dump_config().

### ISIS Database Dump (geek, technical format)

	rr(isis_protocol).    %% Load up record defs, only needed once.
	rp(ets:tab2list(isis_lspdb:get_db(level_1))).

### Force an SPF to run:

	isis_lspdb:schedule_spf(level_1, "Force SPF").

### Show available commands

	isis_cli:<followed by Tab Key>
	module_info/0           module_info/1           pp_binary/2             
	show_adjacencies/1      show_database/0         show_database/1         
	show_database_detail/0  show_database_detail/1  show_interfaces/0       
	show_isis/0             show_nexthops/0         show_rib/0              
	show_routes/1           

The number after the slash is the number of arguments. show_database/1 takes a level (either level_1 or level_2). (tab-completion helps in the console)

### Example configure ISIS and enable it on one interface with encryption
(System ID: 0102.0304.0506, Area 00.0001, level 1 & 2 on eth1, password “mypassword”)

	isis_system:set_system_id(<<1,2,3,4,5,6>>),
	isis_system:add_interface("eth1"),
	isis_system:add_area(<<0,0,1>>),
	isis_system:enable_level("eth1", level_1),
	isis_system:enable_level("eth1", level_2),
	isis_system:set_interface("eth1", level_1, [{encryption, text,
		<<"mypassword">>}]),
	isis_system:set_interface("eth1", level_2, [{encryption, text, 
		<<"mypassword">>}]).

### Set the CSNP interval time (value in seconds (default 10s)

	isis_system:set_interface("eth1", level_1, [{csnp_interval, 20}]).

### Set Hold timer and Hello Interval (value in seconds, default: hold: 10s, hello: 3s)

	isis_system:set_interface("eth1", level_1,
		[{hold_time, 20}, {hello_interval, 5}]).

### Setting LSP max age (value in seconds, default: 1200)

	isis_system:set_state([{lsp_lifetime, 500}]).
