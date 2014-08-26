IS-IS implementation AutoISIS
=============================

## License:
AutoISIS can be used (at your option) under the following GPL or under
a commercial license

1. GPL License<br>
AutoISIS is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.
AutoISIS is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See 
the GNU General Public License for more details.
(see COPYING for full license)

2. Commercial License Usage<br>
Licensees holding a valid commercial AutoISIS may use this file in 
accordance with the commercial license agreement provided with the 
Software or, alternatively, in accordance with the terms contained in 
a written agreement between you and the Copyright Holder.  For
licensing terms and conditions please contact us at 
licensing@netdef.org

## Pre-requisites:
1. Erlang R16 (preferable B03-1 or later)
    - (http://www.erlang.org)
    - Note: Erlang R17 has currently some issue with some required
      libraries.
2. Rebar
    - (https://github.com/rebar/rebar)
3. Relx
    - (https://github.com/erlware/relx)
4. Procket (modified version)
    - (https://git.netdef.org/projects/OSR/repos/procket)

## To build & run:
  **(For more detailed description, check the Doc directory)**

1. Compile rebar, relx & procket as described and put the binary somewhere in your path
2. Download this AutoISIS code
3. Build:
    a. rebar get-deps
    b. rebar compile
    c. relx

You should end up with an application directory in _rel/isis from which
you can start the application:

    cd _rel/isis
    sudo bin/isis start

Once running, you can attach to it:

    sudo bin/isis attach

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

For more commands see the Doc/ Directory
