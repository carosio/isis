-module(web_state).

-include("isis_system.hrl").
-include("isis_protocol.hrl").

-export([init/3, handle/2, terminate/3]).

init(_Type, Req, _Opts) ->
    {ok, Req, no_state}.

handle(Req, State) ->
    %% Strip PIDs from interface list, as file:consult does not like them..
    Is = lists:map(fun(I) -> I#isis_interface{pid = undefined} end,
		   isis_system:list_interfaces()),
    {L1Sids, L2Sids} = isis_system:get_state(system_ids),
    Send = 
	[{system_id, isis_system:system_id()},
	 {interfaces, Is},
	 {lspdb_level_1, fixup_lsps(ets:tab2list(isis_lspdb:get_db(level_1)))},
	 {lspdb_level_2, fixup_lsps(ets:tab2list(isis_lspdb:get_db(level_2)))},
	 {isis_config, ets:tab2list(isis_config)},
	 {rib, ets:tab2list(isis_rib:get_rib_table())},
	 {spf_level_1, format_last_run(spf_summary:last_run(level_1))},
	 {spf_level_2, format_last_run(spf_summary:last_run(level_2))},
	 {frags, isis_system:lsps()},
	 {redistributed_routes, dict:to_list(zclient:get_redistributed_routes())},
	 {l1_sids, prepare_sids(L1Sids)},
	 {l2_sids, prepare_sids(L2Sids)}
	],
    SendBin = erlang:list_to_binary(
		io_lib:format("~p.~n", [Send])),
    {ok, Req2} = cowboy_req:reply(200,
        [
            {<<"content-type">>, <<"application/octet-stream">>},
            {<<"content-disposition">>, <<"attachment; filename=\"isis.state\"">>}
        ], SendBin, Req),
    {ok, Req2, State}.

terminate(_Reason, _Req, _State) ->
    ok.

format_last_run({Time, Level, SPF, Reason, ExtInfo}) ->
    FixNHPid = fun({Afi, {NHA, NHI, _Pid}}) ->
		       {Afi, {NHA, NHI, undefined}}
	       end,
    F = fun({Node, NexthopNode, NextHops, Metric, Routes, Nodes}) ->
		{Node, NexthopNode, lists:map(FixNHPid, NextHops), Metric, Routes, Nodes}
	end,
    {Time, Level, lists:map(F, SPF), Reason, ExtInfo};
format_last_run(M) ->
    M.

fixup_lsps(LSPs) ->
    Now = isis_protocol:current_timestamp(),
    FixupRL = fun(#isis_lsp{remaining_lifetime = L, last_update = U} = LSP) ->
		      LSP#isis_lsp{remaining_lifetime = (L - (Now - U))}
	      end,
    lists:map(FixupRL, LSPs).

prepare_sids(Sids) ->
    dict:map(fun(_SID, Hops) -> gb_trees:map(fun(_M, V1) -> lists:map(fun({A, {B, C, _D}}) -> {A, {B, C, undefined}} end, V1) end, Hops) end, Sids).
