%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% This file is part of AutoISIS.
%%%
%%% License:
%%% This code is licensed to you under the Apache License, Version 2.0
%%% (the "License"); you may not use this file except in compliance with
%%% the License. You may obtain a copy of the License at
%%% 
%%%   http://www.apache.org/licenses/LICENSE-2.0
%%% 
%%% Unless required by applicable law or agreed to in writing,
%%% software distributed under the License is distributed on an
%%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%%% KIND, either express or implied.  See the License for the
%%% specific language governing permissions and limitations
%%% under the License.
%%%
%%% @end
%%% Created : 05 Jul 2015 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------

-record(isis_pdu_state, {
	  parent,        %% Parent module
	  parent_pid,    %% Pid of parent process
	  interface_name,%% Parent interface name
	  circuit_name,  %% Name of our 'circuit'
	  system_id,     %% Cached system_id
	  level,         %% Level in uase
	  authentication = none :: isis_crypto(),
	  level_authentication = none :: isis_crypto(),
	  database = undef,  %% Database Handle
	  ssn = [] :: [binary()],  %% list of pending
	  ssn_timer = undef,
	  csnp_interval,
	  dis_continuation = undef,%% Do we have more CSNP's to send?
	  are_we_dis = false
	 }).
