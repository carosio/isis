%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% Provide some commands to interact with the running erlang isisd,
%%% pending integration with some other CLI system (yang)
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
%%% Created : 12 Apr 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_cli).

-include("isis_system.hrl").
-include("isis_protocol.hrl").

%% API
-export([
	 show_isis/0,
	 %% Database examination
	 show_database/0, show_database/1,
	 show_database_detail/0, show_database_detail/1,
	 %% Interface stuff
	 show_interfaces/0,
	 show_circuits/0,
	 %% Neighbors
	 show_routes/1,     % Output of SPF
	 show_rib/0,        % What we think we've already sent
	 show_nexthops/0,
	 show_adjacencies/1,
	 pp_binary/2
	]).

%%%===================================================================
%%% API
%%%===================================================================
show_isis() ->
    io:format("ISIS system-id ~s~n",
	      [case isis_system:system_id() of
		   undefined -> "undefined";
		   S -> pp_binary(S, ".")
	       end]),
    {Autoconf_Enabled, System_ID_Set} = isis_system:autoconf_status(),
    io:format("Autoconfiguration: ~s (system id set: ~s)~n",
	      [Autoconf_Enabled, System_ID_Set]),
    io:format("Max LSP Age: ~b~n", [isis_system:get_state(lsp_lifetime)]),
    io:format("Areas: ~n", []),
    lists:map(
      fun(F) -> io:format("  ~s~n", [pp_binary(F, ".")]) end,
      isis_system:areas()),
    ok.

show_database() ->
    do_show_database(level_1),
    do_show_database(level_2).
show_database(Level) ->
    do_show_database(Level).

show_database_detail() ->
    do_show_database_detail(level_1),
    do_show_database_detail(level_2).
show_database_detail(Level) ->
    do_show_database_detail(Level).

show_routes(Level) ->
    case spf_summary:last_run(Level) of
	{_Time, _Level, SPF, _Reason, _ExtInfo} ->
	    show_routes(Level, SPF);
	_ ->
	    ok
    end.
show_routes(Level, SPF) ->
    Interfaces = 
	dict:from_list(
	  lists:map(fun(#isis_interface{name = Name, ifindex = IFIndex}) -> {IFIndex, Name} end,
		    isis_system:list_interfaces())),
    SendRoute = 
	fun({#isis_address{afi = AFI, mask = Mask} = A, _Source},
	    NHs, Metric, Nodes) ->
		{NHStr, IFIndex} = 
		    case lists:keyfind(AFI, 1, NHs) of
			{AFI, {NHA, NHI, _Pid}} ->
			    {isis_system:address_to_string(AFI, NHA), NHI};
			false -> {"unknown nexthop", no_ifindex}
		    end,
		AStr = isis_system:address_to_string(A),
		InterfaceStr =
		    case dict:find(IFIndex, Interfaces) of
			{ok, Value} -> Value;
			_ -> "unknown"
		    end,
		%% TODO: This fails as Nodes is a list of a list of nodes - maybe a multipath related problem?
		NodesStrList = lists:map(fun(N) -> isis_system:lookup_name(N) end, Nodes),
		NodesStr = string:join(NodesStrList, ", "),
		io:format("~s/~p via ~s (~s) path: ~s~n",
			  [AStr, Mask, NHStr, InterfaceStr, NodesStr]),
		false;
	   (_, _, _, _) -> false
	end,
    UpdateRib =
	fun({_RouteNode, _NexthopNode, NextHops, Metric,
	     Routes, Nodes}) ->
		lists:filtermap(fun(R) -> SendRoute(R, NextHops, Metric, Nodes) end,
				Routes)
	end,
    lists:map(UpdateRib, SPF),
    ok.

show_rib() ->
    Interfaces = 
	dict:from_list(
	  lists:map(fun(#isis_interface{name = Name, ifindex = IFIndex}) -> {IFIndex, Name} end,
		    isis_system:list_interfaces())),
    IFIndexToName = fun(I) ->
			    case dict:find(I, Interfaces) of
				{ok, Value} -> Value;
				_ -> "unknown"
			    end
		    end,
    RibDB = isis_rib:get_rib_table(),
    RE = ets:tab2list(RibDB),
    PR =
	fun(#isis_route{
	       route = #isis_route_key{
			  prefix = #isis_prefix{afi = AFI,
						address = A,
						mask_length = Mask},
			  source = Source},
	       nexthops = Nexthops,
	       ifindexes = IfIndexes,
	       metric = Metric}) ->
		
		NHs = lists:zip(Nexthops, IfIndexes),
		NHsStr = 
		    lists:foldl(fun(A, Acc) -> Acc ++ A ++ ", " end, "",
				lists:map(fun({NH, IF}) -> lists:flatten(io_lib:format("(~s, ~s)",
										       [isis_system:address_to_string(AFI, NH),
											IFIndexToName(IF)])) end,
					  NHs)),
		FromStr = 
		    case Source of
			undefined -> "";
			#isis_prefix{afi = SAFI, address = SAddress, mask_length = SMask} ->
			    lists:flatten(io_lib:format(" from ~s/~b",
							[isis_system:address_to_string(#isis_address{afi = SAFI,
												     address = SAddress,
												     mask = SMask}),
							 SMask]))
		    end,
		io:format("~s/~b (~b) ~s - via ~s~n",
			  [isis_system:address_to_string(#isis_address{afi = AFI, address = A, mask = Mask}),
			   Mask, Metric, FromStr, NHsStr])
	end,
    lists:map(PR, RE),
    ok.
			    


pp_binary(B, Sep) ->
    pp_binary(B, Sep, []).
pp_binary(<<X:8>>, _, Acc) ->
    lists:flatten(Acc ++ [io_lib:format("~2.16.0B", [X])]);
pp_binary(<<X:8, R/binary>>, Sep, Acc) ->
    pp_binary(R, Sep, Acc ++ [io_lib:format("~2.16.0B~s", [X, Sep])]).

pp_address(#isis_address{afi = ipv4, address = A}) ->
    inet:ntoa(erlang:list_to_tuple([X || <<X:8>> <= <<A:32>>]));
pp_address(#isis_address{afi = ipv6, address = A}) ->
    inet:ntoa(erlang:list_to_tuple([X || <<X:16>> <= <<A:128>>])).

show_interface_level(#isis_interface{pid = Pid}, Level) ->
    {AuthType, AuthKey} =
	case isis_interface:get_state(Pid, Level, authentication) of
	    none -> {none, <<>>};
	    {A, B} -> {A, B}
	end,
    io:format("   Encryption: ~s (key ~p)~n", [AuthType, AuthKey]),
    io:format("   Metric: ~b~n", [isis_interface:get_state(Pid, Level, metric)]),
    io:format("   Priority: ~b~n", [isis_interface:get_state(Pid, Level, priority)]),
    Hello = erlang:trunc(isis_interface:get_state(Pid, Level, hello_interval) / 1000),
    Hold = erlang:trunc(isis_interface:get_state(Pid, Level, hold_time) / 1000),
    io:format("   Hello/Hold Time: ~b / ~b seconds~n", [Hello, Hold]),
    CSNP = erlang:trunc(isis_interface:get_state(Pid, Level, csnp_interval) / 1000),
    io:format("   CSNP Interval: ~b seconds~n", [CSNP]).

show_interfaces_fun(#isis_interface{name = Name,
				    pid = Pid,
				    mac = Mac,
				    metric = Metric,
				    enabled = Enabled,
				    addresses = Addresses,
				    mtu = MTU, mtu6 = MTU6} = I) ->
    io:format("Interface ~p~n", [Name]),
    %% Mash the Mac into something human readable
    MacStr =
	case byte_size(Mac) of
	    6 -> pp_binary(Mac, ":");
	    _ -> "unspecified"
	end,
    io:format("  Mac: ~s MTU: ~B/~B Metric: ~B~n", [MacStr, MTU, MTU6, Metric]),
    io:format("  Enabled: ~p~n", [Enabled]),
    io:format("  Addresses: ~n", []),
    lists:map(fun(A) ->
		      io:format("    ~s/~B~n",
				[pp_address(A), A#isis_address.mask])
	      end, Addresses),
    case Pid of
	undefined -> io:format("  No process for this interface~n");
	_ ->
	    io:format("  Level 1 details~n", []),
	    case isis_interface:get_state(Pid, level_1, authentication) of
		level_not_configured -> io:format("   Level not configured~n");
		_ -> show_interface_level(I, level_1)
	    end,
	    io:format("  Level 2 details~n", []),
	    case isis_interface:get_state(Pid, level_2, authentication) of
		level_not_configured -> io:format("   Level not configured~n");
		_ -> show_interface_level(I, level_2)
	    end
    end.

show_interfaces() ->
    I = isis_system:list_interfaces(),
    lists:map(fun show_interfaces_fun/1, I),
    ok.

show_circuits_fun(#isis_circuit{name = {interface, Name}}) ->
    I = isis_system:get_interface(Name),
    io:format("  ~30s ~5B ~5p ~20s~n",
	      [Name,
	       I#isis_interface.ifindex,
	       I#isis_interface.enabled,
	       I#isis_interface.mode]);
show_circuits_fun(#isis_circuit{name = {ipv6, Addr}}) ->
    io:format("  ~30s ~5B ~5p ~20s~n",
	      [inet_parse:ntoa(Addr),
	       1, true, p2mp]).

show_circuits() ->
    C = isis_system:list_circuits(),
    io:format("  ~30s ~5s ~5s ~20s~n", ["Name", "CtId", "Enbld", "Mode"]),
    lists:map(fun show_circuits_fun/1, C),
    ok.

show_nexthops() ->
    Interfaces = 
	dict:from_list(
	  lists:map(fun(#isis_interface{name = Name, ifindex = IFIndex}) -> {IFIndex, Name} end,
		    isis_system:list_interfaces())),

    lists:map(fun({SID, Addresses}) ->
		      io:format("System: ~s (~p)~n", [isis_system:lookup_name(SID), SID]),
		      lists:map(fun({AFI, {A, NH, _Pid}}) ->
					InterfaceStr =
					    case dict:find(NH, Interfaces) of
						{ok, Value} -> Value;
						_ -> "unknown"
					    end,
					io:format("     ~s (~s)~n",
						  [isis_system:address_to_string(AFI, A), InterfaceStr])
				end, Addresses)
	      end, dict:to_list(isis_system:get_state(system_ids))),
    ok.
					   
show_adjacencies(Level) ->
    Is = isis_system:list_interfaces(),
    lists:map(
      fun(#isis_interface{name = Name, pid = IP}) when is_pid(IP) ->
	      io:format("Adjacencies State for Interface ~s~n",
			[Name]),
	      LPid = isis_interface:get_level_pid(IP, Level),
	      case is_pid(LPid) of
		  true ->
		      AH = dict:to_list(isis_interface_level:get_state(LPid, adjacencies)),
		      lists:map(fun({Mac, {Sid, AdjPid}}) ->
					{_, _, _, [_, _, _, _, Misc]} = sys:get_status(AdjPid),
					Status = proplists:get_value("StateName", proplists:get_value(data, Misc)),
					io:format("~s (~p mac ~p): ~p~n",
						  [isis_system:lookup_name(Sid), Sid, Mac, Status])
				end, AH);
		  _ -> ok
	      end;
	 (_) -> ok
      end, Is),
    ok.

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------

%%%===================================================================
%%% Internal functions
%%%===================================================================
do_show_database_detail(Level) ->
    DB = isis_lspdb:get_db(Level),
    LSPs = ets:tab2list(DB),
    io:format("~s LSP Database~n", [erlang:atom_to_list(Level)]),
    lists:map(fun pp_lsp_detail/1, LSPs),
    io:format("~n", []),
    ok.

do_show_database(Level) ->
    DB = isis_lspdb:get_db(Level),
    LSPs = ets:tab2list(DB),
    io:format("~s LSP Database~n", [erlang:atom_to_list(Level)]),
    lists:map(fun pp_lsp/1, LSPs),
    io:format("~n", []),
    ok.

pp_lsp(LSP) ->
    <<ID:6/binary, PN:8, Frag:8>> = LSP#isis_lsp.lsp_id,
    Now = isis_protocol:current_timestamp(),
    RL = LSP#isis_lsp.remaining_lifetime - (Now - LSP#isis_lsp.last_update),
    io:format("   ~16s.~2.16.0B-~2.16.0B  0x~8.16.0B ~6.10B~n",
	      [isis_system:lookup_name(ID), PN, Frag,
	       LSP#isis_lsp.sequence_number, RL]).

pp_lsp_strings({A, [B]}) when is_list(B) ->
    lists:map(
      fun(C) -> io:format("~-30s ~s~n", [A, C]) end, B);
pp_lsp_strings({A, B}) ->
    io:format("~-30s ~s~n", [A, B]).

pp_lsp_detail(LSP) ->
    <<ID:6/binary, PN:8, Frag:8>> = LSP#isis_lsp.lsp_id,
    Now = isis_protocol:current_timestamp(),
    RL = LSP#isis_lsp.remaining_lifetime - (Now - LSP#isis_lsp.last_update),
    SIDBin = lists:flatten(io_lib:format("~4.16.0B.~4.16.0B.~4.16.0B",
					 [X || <<X:16>> <= ID])),
    LSPStr = io_lib:format("~s.~2.16.0B-~2.16.0B (~s)",
			   [isis_system:lookup_name(ID), PN, Frag, SIDBin]),
    io:format("~-45s  0x~8.16.0B ~6.10B~n",
	      [LSPStr, LSP#isis_lsp.sequence_number, RL]),
    lists:map(
      fun({A, B}) ->
	      case io_lib:printable_list(B) of
		  true -> io:format("   ~-30s ~s~n", [A, B]);
		  _ -> lists:map(fun(C) -> io:format("   ~-30s ~s~n", [A, C]) end,
				 B)
	      end
      end,
      lists:map(fun isis_protocol:pp_tlv/1, LSP#isis_lsp.tlv)).
