%%%-------------------------------------------------------------------
%%% @author Christian Franke <chris@opensourcerouting.org>
%%% @copyright (C) 2015, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% unify_feed - provides a feed of LSP updates
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
%%% Created : 5 July 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(unify_feed).

-include ("isis_system.hrl").
-include ("isis_protocol.hrl").

-export([init/3, websocket_handle/3, websocket_info/3,
	 websocket_init/3, websocket_terminate/3]).

-record(state, {
	  level
	 }).

init(_, _Req, _Opts) ->
    {upgrade, protocol, cowboy_websocket}.

websocket_init(_, Req, _Opts) ->
    {ok, Req, #state{}, 60000}.

websocket_handle({text, <<"start">>}, Req, State) ->
    isis_logger:error("Subscription received"),
    isis_lspdb:subscribe(level_1, self(), struct),
    isis_lspdb:initial_state(level_1, self(), struct),
    OwnId = lists:flatten(io_lib:format("~s.00", [format_id(isis_system:system_id())])),
    Doc = {struct, [
		{operation, "own-id"},
		{id, OwnId}
    ]},
    Json = json2:encode(Doc),
    {reply, {text, list_to_binary(Json)}, Req, State#state{level = level_1}};

websocket_handle(Any, Req, State) ->
    error_logger:error_msg("Received ~p (~p) ~p", [Any, State, ?MODULE]),
    {ok, Req, State}.

websocket_terminate(_Reason, _Req, #state{level = L}) when L =/= undefined ->
    isis_lspdb:unsubscribe(L, self()),
    ok;
websocket_terminate(_, _, _) ->
    ok.

format_id(<<A:16,B:16,C:16>>) ->
	io_lib:format("~4.16.0B.~4.16.0B.~4.16.0B", [A,B,C]);
format_id(<<SysID:6/binary,PN:8>>) ->
	io_lib:format("~s.~2.16.0B", [format_id(SysID), PN]);
format_id(<<LSPID:7/binary, Fragment:8>>) ->
	io_lib:format("~s-~2.16.0B", [format_id(LSPID), Fragment]).

handle_reach(#isis_tlv_extended_reachability_detail{
		neighbor = N,
		sub_tlv = S
	     }, Acc) ->
	Rv = [{neighbor, lists:flatten(format_id(N))}],
	Rv2 = Rv ++ lists:foldl(fun (#isis_subtlv_eis_unify_interface{name = Name}, Acc2) -> Acc2 ++ [{port, Name}];
				    (_, Acc2) -> Acc2
				end, [], S),
	Acc ++ [{struct,Rv2}].

handle_tlv(#isis_tlv_dynamic_hostname{hostname = Hostname}, Acc) ->
	Acc ++ [{hostname, Hostname}];
handle_tlv(#isis_tlv_unify_interfaces{interfaces = Interfaces}, Acc) ->
	Acc ++ [{interfaces, {array, Interfaces}}];
handle_tlv(#isis_tlv_extended_reachability{reachability = EIR}, Acc) ->
	Acc ++ [{links, {array, lists:foldl(fun handle_reach/2, [], EIR)}}];
handle_tlv(_, Acc) ->
	Acc.

websocket_info({lsp_update, {add, level_1, #isis_lsp{lsp_id = LSP_Id, tlv = TLV}}}, Req, State) ->
    Info = {struct, lists:foldl(fun handle_tlv/2, [], TLV)},
    Doc = {struct, [
		{operation, "add"},
		{id, lists:flatten(format_id(LSP_Id))},
		{info, Info}
    ]},
    Json = json2:encode(Doc),
    {reply, {text, list_to_binary(Json)}, Req, State};
websocket_info({lsp_update, {delete, level_1, LSP_Id}}, Req, State) ->
    Doc = {struct, [
		{operation, "delete"},
		{id, lists:flatten(format_id(LSP_Id))}
    ]},
    Json = json2:encode(Doc),
    {reply, {text, list_to_binary(Json)}, Req, State};

websocket_info(Info, Req, State) ->
    error_logger:info_msg("~p unknown info msg ~p", [self(), Info]),
    {noreply, Req, State}.
