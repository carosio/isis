IS-IS implementation
====================

Pre-requisites:
  Erlang R16 (preferable B03-1 or later)
    (http://www.erlang.org)
  Rebar
    (https://github.com/basho/rebar)

To build:
  Compile rebar as described and put the binary somewhere in your path

  Download the erlang-isis code
  make deps
  make compile
  rebar generate

You should end up with an application directory in rel/isis from which
you can start the application:

You will want to put 'deps/procket/priv/procket' into
/usr/local/bin. Ensure that you can start this using 'sudo'. Then you
can start the application:

  cd rel/isis
  bin/isis start

Once running, you can attach to it:

  bin/isis attach

Use Control-D to detach.

To examine interfaces, for example:

(isis@127.0.0.1)1> isis_cli:show_interfaces().
Interface "eth0"
  Mac: 00:0C:29:96:E2:79 MTU: 1500/1500 Metric: 10
  Enabled: true
  Addresses:
    172.16.3.224/24
    FE80::20C:29FF:FE96:E279/64
Interface "eth1"
  Mac: 00:0C:29:96:E2:83 MTU: 1500/1500 Metric: 10
  Enabled: true
  Addresses:
    192.168.247.152/24
    2001:8B0:A:A:B46B:A129:73FC:66D2/64
    2001:8B0:A:A:20C:29FF:FE96:E283/64
    FE80::20C:29FF:FE96:E283/64
Interface "lo"
  Mac: unspecified MTU: 65536/65536 Metric: 10
  Enabled: false
  Addresses:
    127.0.0.1/8
    ::1/128
ok

To examine the LSP database:

(isis@127.0.0.1)2> isis_cli:show_database().
level_1 LSP Database
 autoconf-C2996E2.00-00  0x00000004    123
         ti-4.2.1.00-00  0x00000290   1182
         ti-4.2.1.01-00  0x0000001F    692
level_2 LSP Database
 autoconf-C2996E2.00-00  0x00000003   1148

