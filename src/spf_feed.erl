%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% spf_feed provides a feed of the output of the SPF run so we can
%%% use it to generate the graph in a webpage.
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
%%% Created : 18 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(spf_feed).

-include ("../deps/yaws/include/yaws_api.hrl").
-include ("isis_system.hrl").

-export([out/1, handle_message/1, terminate/2]).

-export([handle_call/3, handle_info/2, handle_cast/2, code_change/3]).

-record(link, {source,
	       source_name,
	       target,
	       target_name,
	       value}).

out(A) ->
  case get_upgrade_header(A#arg.headers) of
    undefined ->
	  
	  {content, "text/plain", "You are not a websocket, Go away!"};
          "websocket" ->      Opts = [
				      {keepalive,         true},
				      {keepalive_timeout, 10000},
				      {drop_on_timeout,   true}
         ],
      {websocket, spf_feed, Opts};
    Any ->
      error_logger:error_msg("Got ~p from the upgrade header!", [Any])
  end.

handle_message({text, <<"start">>}) ->
    spf_summary:subscribe(self()),
    M = generate_update(0, level_1, [], "Startup"),
    {reply, {text, list_to_binary(M)}};

handle_message({close, Status, _Reason}) ->
    {close, Status};

handle_message(Any) ->
    error_logger:error_msg("Received at spf_feed ~p ", [Any]),
    noreply.

terminate(_Reason, _State) ->
    spf_summary:unsubscribe(self()),
    ok.

 handle_info({spf_summary, {Time, level_1, SPF, Reason}}, State) ->
    Json = generate_update(Time, level_1, SPF, Reason),
    {reply, {text, list_to_binary(Json)}, State};
 handle_info({spf_summary, {_, level_2, _, _Reason}}, State) ->
    {noreply, State};


%% Gen Server functions
handle_info(Info, State) ->
    error_logger:info_msg("~p unknown info msg ~p", [self(), Info]),
    {noreply, State}.

handle_cast(Msg, State) ->
    error_logger:info_msg("~p unknown msg ~p", [self(), Msg]),
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

generate_update(Time, Level, SPF, Reason) ->
    %% Get ourselves an ifindex->name mapping...
    Interfaces = 
	dict:from_list(
	  lists:map(fun(#isis_interface{name = Name, ifindex = IFIndex}) -> {IFIndex, Name} end,
		    isis_system:list_interfaces())),
    SPFLinks = isis_lspdb:links(isis_lspdb:get_db(Level)),
    Links = lists:map(fun({{<<A:7/binary>>,
			   <<B:7/binary>>}, Weight}) ->
			      L = #link{source = lists:flatten(io_lib:format("~p", [A])),
					source_name = isis_system:lookup_name(A),
					target = lists:flatten(io_lib:format("~p", [B])),
					target_name = isis_system:lookup_name(B),
					value = Weight},
			      {struct, lists:zip(record_info(fields, link),
						 tl(tuple_to_list(L)))}
		      end, dict:to_list(SPFLinks)),

    SendRoute = 
	fun({#isis_address{afi = AFI, mask = Mask} = A, Source},
	    NHs, Metric, Paths) ->
		%% Extract NHs matching AFI, map to {Address, Interface} string pair
		NHList = lists:filtermap(
			   fun({AFI, {NHA, NHI, _}}) ->
				   NHIS =
				       case dict:find(NHI, Interfaces) of
					   {ok, Value} -> Value;
					   _ -> "unknown"
				       end,
				   {true, {isis_system:address_to_string(AFI, NHA),
					   NHIS}};
			      ({_, {_, _, _}}) -> false
			   end, NHs),
		{NexthopList, InterfaceList} = lists:unzip(NHList),
		AStr = isis_system:address_to_string(A),
		FromStr = 
		    case Source of
			undefined -> "";
			#isis_address{afi = SAFI, address = SAddress, mask = SMask} ->
			    lists:flatten(io_lib:format("~s/~b",
							[isis_system:address_to_string(#isis_address{afi = SAFI,
												     address = SAddress,
												     mask = SMask}),
							 SMask]))
		    end,
		PathConv = fun(Path) -> string:join(lists:map(fun(P) -> isis_system:lookup_name(P) end, Path), ", ") end,
		NodesStrList = lists:map(PathConv, Paths),
		NodesStr = "(" ++ string:join(NodesStrList, ", ") ++ ")",
		{true, {struct, [{"afi", atom_to_list(AFI)},
				 {"address", AStr},
				 {"mask", Mask},
				 {"from", FromStr},
				 {"nexthop", NexthopList},
				 {"interface", InterfaceList},
				 {"nodepath", NodesStr}]}};
	   (_, _, _, _) -> false
	end,
    UpdateRib =
	fun({_RouteNode, _NexthopNode, NextHops, Metric,
	     Routes, Nodes}) ->
		lists:filtermap(fun(R) -> SendRoute(R, NextHops, Metric, Nodes) end,
				Routes)
	end,
    Rs = lists:map(UpdateRib, SPF),
    json2:encode({struct, [{"Time", Time}, {"links", {array, Links}}, {"rib", {array, Rs}},
			   {"Reason", Reason}]}).
