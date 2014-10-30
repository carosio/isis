IS-IS implementation AutoISIS
=============================

## License:
AutoISIS s licensed to you under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License. You may obtain a copy of the License at
 
http://www.apache.org/licenses/LICENSE-2.0
 
Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.

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
