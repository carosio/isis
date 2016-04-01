%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% lsp_feed - provides a feed of LSP updates
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
-module(lsp_feed).

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

websocket_handle({text, <<"start level_1">>}, Req, State) ->
    isis_logger:error("Subscription for l1 received"),
    isis_lspdb:subscribe(level_1, self(), web),
    isis_lspdb:initial_state(level_1, self(), web),
    {ok, Req, State#state{level = level_1}};

websocket_handle({text, <<"start level_2">>}, Req, State) ->
    isis_lspdb:subscribe(level_2, self()),
    {reply, {text, <<"buh">>}, Req, State#state{level = level_2}};

websocket_handle(Any, Req, State) ->
    error_logger:error_msg("Received ~p (~p) ~p", [Any, State, ?MODULE]),
    {ok, Req, State}.

websocket_terminate(_Reason, _Req, #state{level = L}) when L =/= undefined ->
    isis_lspdb:unsubscribe(L, self()),
    ok;
websocket_terminate(_, _, _) ->
    ok.

websocket_info({lsp_update, Message}, Req, State) ->
    {reply, {text, Message}, Req, State};
websocket_info(Any, Req, State) ->
    error_logger:error_msg("Received info ~p (~p) ~p", [Any, State, ?MODULE]),
    {ok, Req, State}.
