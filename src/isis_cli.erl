%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% Provide some commands to interact with the running erlang isisd,
%%% pending integration with some other CLI system (yang)
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
	 %% Interface stuff
	 show_interfaces/0
	 %% Neighbors
	 %%show_adjacencies/0
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

show_interface_level({Name, #isis_interface{pid = Pid}}, Level) ->
    {AuthType, AuthKey} = isis_interface:get_state(Pid, Level, authentication),
    io:format("   Encryption: ~s (key ~p)~n", [AuthType, AuthKey]).

show_interfaces_fun({Name, #isis_interface{pid = Pid,
					   mac = Mac,
					   metric = Metric,
					   enabled = Enabled,
					   addresses = Addresses,
					   mtu = MTU, mtu6 = MTU6}} = I) ->
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
    I = dict:to_list(isis_system:list_interfaces()),
    lists:map(fun show_interfaces_fun/1, I),
    ok.
		      

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------

%%%===================================================================
%%% Internal functions
%%%===================================================================
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
