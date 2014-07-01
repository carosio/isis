%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% spf_feed provides a feed of the output of the SPF run so we can
%%% use it to generate the graph in a webpage.
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
	       target,
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
    error_logger:error_msg("Received ~p", [Any]),
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
			      L = #link{source = isis_system:lookup_name(A),
					target = isis_system:lookup_name(B),
					value = Weight},
			      {struct, lists:zip(record_info(fields, link),
						 tl(tuple_to_list(L)))}
		      end, dict:to_list(SPFLinks)),

    SendRoute = 
	fun({#isis_address{afi = AFI, mask = Mask} = A, _Source},
	    NHs, Metric, Nodes) ->
		{NHAfi, {NH, IFIndex}} = 
		    case lists:nth(1, NHs) of
			{ipv4, NHA} -> {ipv4, {NHA, no_ifindex}};
			{ipv6, {NHA, NHI}} -> {ipv6, {NHA, NHI}}
		    end,
		AStr = isis_system:address_to_string(A),
		NHStr = isis_system:address_to_string(NHAfi, NH),
		InterfaceStr =
		    case dict:find(IFIndex, Interfaces) of
			{ok, Value} -> Value;
			_ -> "unknown"
		    end,
		NodesStrList = lists:map(fun(N) -> isis_system:lookup_name(N) end, Nodes),
		NodesStr = string:join(NodesStrList, ", "),
		{true, {struct, [{"afi", atom_to_list(AFI)},
				 {"address", AStr},
				 {"mask", Mask},
				 {"nexthop", NHStr},
				 {"interface", InterfaceStr},
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
