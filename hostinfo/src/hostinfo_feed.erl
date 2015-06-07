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
%%% Created : 6 Dec 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(hostinfo_feed).

-include ("../../deps/yaws/include/yaws_api.hrl").
-include ("../../src/isis_system.hrl").
-include ("../../src/isis_protocol.hrl").

-export([out/1, init/1, handle_message/2, terminate/2]).

-export([handle_call/3, handle_info/2, handle_cast/2, code_change/3]).

-record(state, {
	 }).

out(A) ->
  case get_upgrade_header(A#arg.headers) of
    undefined ->
	  
	  {content, "text/plain", "You are not a websocket, Go away!"};
          "websocket" ->      Opts = [
				      {keepalive,         true},
				      {keepalive_timeout, 10000},
				      {drop_on_timeout,   true}
         ],
      {websocket, hostinfo_feed, Opts};
    Any ->
      error_logger:error_msg("Got ~p from the upgrade header!", [Any])
  end.

init(_Args) ->
    {ok, #state{}}.

handle_message({text,<<"start">>}, State) ->
    hostinfo:subscribe(),
    {noreply, State#state{}};

handle_message({close, Status, _Reason}, State) ->
    {close, Status, State};

handle_message(Any, State) ->
    error_logger:error_msg("buger ~p (~p)", [Any, State]),
    {noreply, State}.

terminate(_Reason, #state{}) ->
    hostinfo:unsubscribe(),
    ok;
terminate(_, _) ->
    ok.

handle_info({host_update, Message}, State) ->
    {reply, {text, Message}, State};

%% Gen Server functions
handle_info(Info, State) ->
    error_logger:info_msg("~p unknown info msg ~p", [self(), Info]),
    {noreply, State}.

handle_cast(Msg, State) ->
    {noreply, State}.

handle_call(Request, _From, State) ->
    error_logger:info_msg("~p unknown call ~p", [self(), Request]),
    {stop, {unknown_call, Request}, State}.

code_change(_OldVsn, Data, _Extra) ->
    {ok, Data}.

get_upgrade_header(#headers{other=L}) ->
    lists:foldl(fun({http_header,_,K0,_,V}, undefined) ->
                        K = case is_atom(K0) of
                                true ->
                                    atom_to_list(K0);
                                false ->
                                    K0
                            end,
                        case string:to_lower(K) of
                            "upgrade" ->
                                string:to_lower(V);
                            _ ->
                                undefined
                        end;
                   (_, Acc) ->
                        Acc
                end, undefined, L).

generate_update() ->
    ok.
