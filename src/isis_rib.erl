%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% ISIS Rib - processes the results of the SPF calculations into
%%% something we can feed to the RIB, taking into account our previous
%%% state (ie. send only the difference).
%%%
%%% @end
%%% Created :  1 Apr 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_rib).

-behaviour(gen_server).

-include("zclient.hrl").
-include("isis_system.hrl").
-include_lib("stdlib/include/ms_transform.hrl").

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
	  rib
	 }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    spf_summary:subscribe(self()),
    Table = ets:new(isis_rib, [ordered_set,
			       {keypos, #zclient_route.prefix}]),
    {ok, #state{rib = Table}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info({spf_summary, {Time, Level, SPF, _Reason}}, State) ->
    NewState = process_spf(SPF, State),
    {noreply, NewState};
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
extract_prefixes(State) ->
    F = ets:fun2ms(fun(#zclient_route{prefix = P}) ->
			   P
		   end),
    ets:select(State#state.rib, F).

process_spf(SPF, State) ->
    SendRoute = 
	fun({#isis_address{afi = AFI, address = Address, mask = Mask}, Source},
	    NHs, Metric, Added) ->
		SourceP = case Source of
			      #isis_address{afi = SAFI, address = SAddress,
					    mask = SMask} ->
				  #zclient_prefix{afi = SAFI, address = SAddress,
						  mask_length = SMask};
			      _ -> undefined
			  end,
		%% FIX zclient to handle multiple nexthops..
		{Nexthops, IfIndexes} = lists:foldl(
					  fun({NHAfi,{A, I}}, {TNHs, TIFs})
						when NHAfi =:= AFI -> {[A | TNHs], [I | TIFs]};
					     (_, Acc) -> Acc
					  end, {[], []}, NHs),
		case {Nexthops, IfIndexes} of
		    {[], []} ->
			Added;
		    {_, _} ->
			P = #zclient_prefix{afi = AFI, address = Address, mask_length = Mask},
			R = #zclient_route{prefix = P, nexthops = Nexthops, ifindexes = IfIndexes,
					   metric = Metric, source = SourceP},
			case ets:lookup(State#state.rib, R) of
			    [] ->
				%% No prior route, so install into the RIB
				ets:insert(State#state.rib, R),
				zclient:add(R);
			    [C] ->
				case C =:= R of
				    true ->
					%% Prior route matches this one, no-op...
					Added;
				    _ ->
					%% Prior route is different
					ets:insert(State#state.rib, R),
					zclient:add(R)
				end
			end,
			sets:add_element(P, Added);
		    _ -> Added
		end
	end,
    UpdateRib =
	fun({_RouteNode, _NexthopNode, NextHops, Metric,
	     Routes, _Nodes}, AddSet) ->
		lists:foldl(fun(R, AddSet2) -> SendRoute(R, NextHops, Metric, AddSet2) end,
			    AddSet, Routes)
	end,
    Installed = lists:foldl(UpdateRib, sets:new(), SPF),
    Present = sets:from_list(extract_prefixes(State)),
    Delete = sets:subtract(Present, Installed),
    lists:map(fun(P) -> zclient:delete(P) end, sets:to_list(Delete)),
    State.
