%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@ubuntu>
%%% @copyright (C) 2015, Rick Payne
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
%%% Created : 24 Mar 2015 by Rick Payne <rickp@ubuntu>
%%%-------------------------------------------------------------------
-module(isis_logger).

%% API
-export([
	 debug/1, debug/2,
	 info/1, info/2,
	 warning/1, warning/2,
	 error/1, error/2
	]).

%%%===================================================================
%%% API
%%%===================================================================
debug(String) ->
    log(debug, self(), String, []).
debug(String, Items) ->
    log(debug, self(), String, Items).

info(String) ->
    log(info, self(), String, []).
info(String, Items) ->
    log(info, self(), String, Items).

warning(String) ->
    log(warning, self(), String, []).
warning(String, Items) ->
    log(warning, self(), String, Items).

error(String) ->
    log(error, self(), String, []).
error(String, Items) ->
    log(error, self(), String, Items).

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------

%%%===================================================================
%%% Internal functions
%%%===================================================================
log(Level, Pid, String, Items) ->
    case code:is_loaded(lager) of
	false ->
	    io:fwrite("ISIS: ~p ~p ~s ~p~n", [Pid, Level, String, Items]);
	_ ->
	    lager:log(Level, Pid, String, Items)
    end.
