%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% Netlink interface
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
%%% Created : 04 Aug 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_netlink).

-behaviour(gen_server).

-include ("isis_system.hrl").
-include_lib ("gen_netlink/include/netlink.hrl").

%% API
-export([start_link/1,
	 %% Subscription to updates...
	 subscribe/1, unsubscribe/1,
	 %% Sending information to the RIB
	 add/1, delete/1, request_redist/1,
	 get_redistributed_routes/0,
	 %% Debug
	 get_state/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
	  listeners :: dict(),
	  interfaces :: dict(),        %% Map ifindex -> record
	  routes :: dict(),            %% Route Key -> {[NH], [IfIndex]}
	  table = main,
	  scope = universe,
	  protocol = 17,
	  metric_scale = 100
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
start_link(Args) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, Args, []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
subscribe(Pid) ->
    gen_server:call(?MODULE, {subscribe, Pid}).

unsubscribe(Pid) ->
    gen_server:call(?MODULE, {unsubscribe, Pid}).

get_state() ->
    gen_server:call(?MODULE, {get_state}).

add(#isis_route{} = Route) ->
    gen_server:call(?MODULE, {send_route, Route});
add(Unknown) ->
    isis_logger:error("netlink:add called with unknown argument ~p", [Unknown]),
    unknown.

delete(#isis_route_key{} = RouteKey) ->
    gen_server:call(?MODULE, {delete_route, RouteKey});
delete(Unknown) ->
    isis_logger:error("netlink:delete called with unknown argument ~p", [Unknown]),
    unknown.

request_redist(Type) ->
    gen_server:call(?MODULE, {request_redist, Type}).

get_redistributed_routes() ->
    gen_server:call(?MODULE, {get_redistributed_routes}).

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
init([{type, _}]) ->
    application:ensure_all_started(gen_netlink),
    netlink:subscribe(netlink, self(), [rt]),
    Req = #rtnetlink{type = getlink,
		     flags = [match, root, request],
		     pid = 0,
		     msg = {packet, 0, 0, []}},
    Interfaces = 
	case netlink:request(rt, Req) of
	    {ok, NetlinkInterfaces} ->
		dict:from_list(
		  lists:map(fun(#isis_interface{ifindex = IfIndex} = Int) -> {IfIndex, Int} end,
			    lists:map(fun convert_netlink_interface_to_isis/1,
				      NetlinkInterfaces)));
	    Error -> isis_logger:error("Error requesting interfaces: ~p", [Error]),
		     dict:new()
	end,
    InitialState = #state{listeners = dict:new(), interfaces = Interfaces,
			  routes = dict:new()},
    UpdatedState = 
	case netlink:request(rt, Req#rtnetlink{type = getaddr}) of
	    {ok, Addresses} ->
		CA = lists:filtermap(fun convert_netlink_connected_to_isis/1,
			       Addresses),
		lists:foldl(fun({IfIndex, A}, #state{interfaces = Is} = S) ->
				    case dict:find(IfIndex, Is) of
					{ok, I} -> update_interface_address(add, A, I, S);
					error -> S
				    end
			    end, InitialState, CA);
	    _ -> Interfaces
	end,
    StartState = 
	lists:foldl(
	  fun(Family, S1) ->
		  case netlink:request(rt,
				       #rtnetlink{type = getroute, flags = [match,root,request],
						  seq = 0, pid = 0,
						  msg = {Family,0,0,0,8,unspec,29,unspec,[],[]}}) of
		      {ok, Routes} ->
			  lists:foldl(fun(#rtnetlink{type = newroute,
						     msg = {_, _, _, _, _, P, _, _, _, _}} = M, S)
					    when P =:= S#state.protocol ->
					      %% Delete routes from a previous run
					      netlink:request(rt, M#rtnetlink{type = delroute}),
					      S;
					 (#rtnetlink{type = newroute} = M, S) ->
					      process_netlink_update(M, S);
					 (_, S) ->
					      S
				      end, S1, Routes);
		      _ -> S1
		  end
	  end,  UpdatedState, [inet, inet6]),
    {ok, StartState};
init(Args) ->
    io:format("Unknown args: ~p~n", [Args]),
    {stop, netlink_failure}.
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
handle_call({subscribe, Pid}, _From, #state{listeners = Clients} = State) ->
    erlang:monitor(process, Pid),
    send_current_state(Pid, State),
    {reply, ok, State#state{listeners = dict:store(Pid, [], Clients)}};
handle_call({unsubscribe, Pid}, _From, State) ->
    NewState = remove_client(Pid, State),
    {reply, ok, NewState};
handle_call({send_route, Route}, _From, State) ->
    {reply, ok, install_route_via_netlink(Route, State)};
handle_call({delete_route, RouteKey}, _From, State) ->
    {reply, ok, delete_route_via_netlink(RouteKey, State)};
handle_call({get_state}, _From, State) ->
    {reply, State, State};
handle_call({get_redistributed_routes}, _From, State) ->
    {reply, State#state.routes, State};
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
handle_cast(Msg, State) ->
    isis_logger:error("Handling cast: ~p", [Msg]),
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
handle_info({rtnetlink, Msgs}, State) ->
    NewState = 
	lists:foldl(fun(M, S) -> process_netlink_update(M, S) end,
		    State, Msgs),
    {noreply, NewState};

handle_info(Info, State) ->
    isis_logger:error("Received unknown message: ~p", [Info]),
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

remove_client(Pid, #state{listeners = Clients} = State) ->
    NewClients =
	case dict:find(Pid, Clients) of
	    {ok, _Value} ->
		dict:erase(Pid, Clients);
	    error ->
		Clients
	end,
    State#state{listeners = NewClients}.

%%--------------------------------------------------------------------
%% @doc Add this address to the list.
%% @end
%% --------------------------------------------------------------------
add_or_update_address(add, Address, Addresses) ->
    %% Filter the list to see if it already contains this address...
    F = fun(A) when Address =:= A -> true;
	   (_) -> false
	end,						       
    Count = length(lists:filter(F, Addresses)),
    %% If the length of the filtered list is 1, we have no work to do
    case Count of
	1 -> Addresses;
	0 -> Addresses ++ [Address];	    
	V -> io:format("Filter got ~p~n", [V])	     
    end;
add_or_update_address(del, Address, Addresses) ->
    F = fun(A) when Address =:= A ->
		false;
	   (_) -> true
	end,
    lists:filter(F, Addresses).

%%--------------------------------------------------------------------
%% @doc Send out an update to all listeners...
%% @end
%% --------------------------------------------------------------------
update_interface_address(AddDel, Address,
			 #isis_interface{addresses = A} = Interface,
			 State) ->
    L = add_or_update_address(AddDel, Address, A),
    I = Interface#isis_interface{addresses = L},
    D = dict:store(Interface#isis_interface.ifindex, I,
		  State#state.interfaces),
    Action = case AddDel of
		 add -> add_address;
		 del -> del_address
	     end,
    update_listeners({Action, I#isis_interface.name, Address},
		     State),
    State#state{interfaces = D}.

%%--------------------------------------------------------------------
%% @doc Send out an update to all listeners...
%% @end
%% --------------------------------------------------------------------
update_listeners(Msg, #state{listeners = Listeners}) ->
    Pids = dict:fetch_keys(Listeners),
    lists:foreach(fun(Pid) -> Pid ! Msg end, Pids).

%%--------------------------------------------------------------------
%% @doc Send the current state to a new subscriber, as discrete events.
%% @end
%%--------------------------------------------------------------------
send_current_state(Pid, #state{interfaces = Interfaces,
			       routes = Routes}) ->
    %% Now send interface information
    I = dict:to_list(Interfaces),
    F = fun({_, A}) -> send_interface(A, Pid) end,
    lists:map(F, I),
    R = dict:to_list(Routes),
    F2 = fun({Key, Hops}) -> send_route_to_pid(Key, Hops, Pid) end,
    lists:map(F2, R),
    ok.

%%--------------------------------------------------------------------
%% @doc
%% Handle the addition/deletion of a route_key->nexthop
%% Note that we will get a route once per each nexthop, so we will keep
%% our own cache and give them to subscribers as a set...
%% @end
%%--------------------------------------------------------------------
update_route(add, Key, NextHop, IfIndex,
	     #state{routes = Routes} = State) ->
    NewRoutes = 
	case dict:find(Key, Routes) of
	    {ok, Hops} ->
		case lists:member({NextHop, IfIndex}, Hops) of
		    true -> %% Already have this hop, no-op...
			Routes;
		    _ -> %% Add this {nh, ifindex} to the set
			NewHops = Hops ++ [{NextHop, IfIndex}],
			send_route(Key, NewHops, State),
			dict:store(Key, NewHops, Routes)
		end;
	    _ -> %% No Route
		NewHops = [{NextHop, IfIndex}],
		send_route(Key, NewHops, State),
		dict:store(Key, NewHops, Routes)
	end,
    State#state{routes = NewRoutes};		
update_route(del, Key, NextHop, IfIndex,
	    #state{routes = Routes} = State) ->
    NewRoutes =
	case dict:find(Key, Routes) of
	    {ok, Hops} ->
		NewHops = lists:filter(fun(Z) -> Z =/= {NextHop, IfIndex} end, Hops),
		case length(NewHops) =:= length(Hops) of
		    true -> %% Nothing to do
			Routes;
		    _ ->
			case length(NewHops) of
			    0 ->
				send_route(Key, [], State),
				dict:erase(Key, Routes);
			    _ ->
				send_route(Key, NewHops, State),
				dict:store(Key, NewHops, Routes)
			end
		end;
	    _ -> %% No such route, no-op
		Routes
	end,
    State#state{routes = NewRoutes}.		

%%--------------------------------------------------------------------
%% @doc
%% Send an interface to a subscriber - noting we don't send lo for now..
%% @end
%%--------------------------------------------------------------------
send_interface(#isis_interface{name = Name} = A, Pid)
  when Name =/= "lo" ->
    Z = A#isis_interface{addresses = []},
    Pid ! {add_interface, Z},
    lists:map(fun(B) -> Pid ! {add_address, A#isis_interface.name, B} end,
	      A#isis_interface.addresses);
send_interface(_, _Pid) ->
    ok.

%%--------------------------------------------------------------------
%% @doc
%% Send a route to our subscribers
%% @end
%%--------------------------------------------------------------------
send_route(#isis_route_key{} = Key, [], State) ->
    R = #isis_route{route = Key},
    update_listeners({redistribute_delete, R}, State);
send_route(#isis_route_key{} = Key, Hops, State) ->
    {NHs, IFs} = lists:unzip(Hops),
    R = #isis_route{route = Key,
		    metric = 10,
		    nexthops = NHs,
		    ifindexes = IFs},
    update_listeners({redistribute_add, R}, State).

send_route_to_pid(#isis_route_key{} = Key, Hops, Pid) ->
    {NHs, IFs} = lists:unzip(Hops),
    R = #isis_route{route = Key,
		    metric = 10,
		    nexthops = NHs,
		    ifindexes = IFs},
    Pid ! {redistribute_add, R}.

%%--------------------------------------------------------------------
%% @doc
%% Take a netlink interface and convert to an isis_interface
%% @end
%%--------------------------------------------------------------------
convert_netlink_interface_to_isis(
  #rtnetlink{msg =
		 {_Family, _Type, IfIndex, _Flags, _, Attributes}}) ->
    #isis_interface{
       name = proplists:get_value(ifname, Attributes),
       mac = proplists:get_value(address, Attributes),
       enabled = (up =:= proplists:get_value(operstate, Attributes)),
       ifindex = IfIndex,
       mtu = proplists:get_value(mtu, Attributes),
       mtu6 = proplists:get_value(mtu, Attributes)
      }.

%%--------------------------------------------------------------------
%% @doc
%% Take a netlink link addr and convert to an isis_prefix
%% @end
%%--------------------------------------------------------------------
convert_netlink_connected_to_isis(
  #rtnetlink{msg = {Family, Masklen, Flags, _Scope, IfIndex, Properties}})
  when Flags band 1 =:= 0 ->
    Address = proplists:get_value(address, Properties),
    {true, create_isis_address(Family, Address, Masklen, IfIndex)};
convert_netlink_connected_to_isis(_) ->
    false.

%%--------------------------------------------------------------------
%% @doc
%% Take a netlink route and convert to an isis_route_key and details
%% @end
%%--------------------------------------------------------------------
convert_netlink_route_to_isis(
  #rtnetlink{msg = {Family, Masklen, SrcLen, _Tos, _Table, Protocol, _Scope, unicast,
		    _Flags, Properties}}, State)
  when Protocol =/= State#state.protocol ->
    Dst = proplists:get_value(dst, Properties),
    Src = proplists:get_value(src, Properties),
    NH = proplists:get_value(gateway, Properties),
    IfIndex = proplists:get_value(oif, Properties),
    {_, DstP} = create_isis_address(Family, Dst, Masklen, IfIndex),
    SrcP = case Src of
	       undefined -> undefined;
	       _ -> {_, S1} = create_isis_address(Family, Src, SrcLen, IfIndex),
		    S1
	   end,
    case NH of
	undefined -> false;
	_ -> {_, S2} = create_isis_address(Family, NH, 0, IfIndex),
	     NHP = S2#isis_prefix.address,
	     RouteKey = #isis_route_key{prefix = DstP, source = SrcP},
	     {RouteKey, NHP, IfIndex}
    end;
convert_netlink_route_to_isis(_, _) ->
    false.

%%--------------------------------------------------------------------
%% @doc
%% Generate an isis_prefix from the usual details
%% @end
%%--------------------------------------------------------------------
create_isis_address(inet, undefined, Len, IfIndex) ->
    {IfIndex, #isis_prefix{afi = ipv4, address = 0, mask_length = Len}};
create_isis_address(inet6, undefined, Len, IfIndex) ->
    {IfIndex, #isis_prefix{afi = ipv6, address = 0, mask_length = Len}};
create_isis_address(inet, Address, Len, IfIndex) ->
    <<I:32>> = << <<X:8>> || X <- tuple_to_list(Address) >>,
    {IfIndex, #isis_prefix{afi = ipv4, address = I, mask_length = Len}};
create_isis_address(inet6, Address, Len, IfIndex) ->
    <<I:128>> = << <<X:16>> || X <- tuple_to_list(Address) >>,
    {IfIndex, #isis_prefix{afi = ipv6, address = I, mask_length = Len}}.

%%--------------------------------------------------------------------
%% @doc
%% Process a netlink update
%% @end
%%--------------------------------------------------------------------
process_netlink_update(#rtnetlink{type = Cmd} = RTM, State)
  when Cmd =:= newaddr; Cmd =:= deladdr ->
    NewState = 
	case convert_netlink_connected_to_isis(RTM) of
	    {true, {IfIndex, Connected}} ->
		case dict:find(IfIndex, State#state.interfaces) of
		    {ok, I} -> update_interface_address(case Cmd of
							    newaddr -> add;
							    deladdr -> del
							end, Connected, I, State);
		    error -> State
		end;
	    _ ->
		State
	end,
    NewState;
process_netlink_update(#rtnetlink{type = Cmd} = RTM, State)
  when Cmd =:= newroute; Cmd =:= delroute ->
    NewState = 
	case convert_netlink_route_to_isis(RTM, State) of
	    false -> State;
	    {RouteKey, NextHop, IfIndex} ->
		update_route(case Cmd of
				 newroute -> add;
				 delroute -> del
			     end, RouteKey, NextHop, IfIndex, State)
	end,
    NewState;
process_netlink_update(#rtnetlink{type = T, msg = Msg}, State) ->
    isis_logger:debug("Ignoring netlink message type ~p (~p)", [T, Msg]),
    State.

convert_addr(ipv4, A) when is_binary(A) ->
    Size = bit_size(A),
    Shift = 32 - Size,
    <<A1:Size>> = A,
    A2 = A1 bsl Shift,
    list_to_tuple([ X || <<X:8>> <= <<A2:32>> ]);
convert_addr(ipv6, A) when is_binary(A) ->
    Size = bit_size(A),
    Shift = 128 - Size,
    <<A1:Size>> = A,
    A2 = A1 bsl Shift,
    list_to_tuple([ X || <<X:16>> <= <<A2:128>> ]);
convert_addr(_, A) when is_tuple(A) ->
    A.

install_route_via_netlink(#isis_route
			  {route = 
			       #isis_route_key
			   {prefix =
				#isis_prefix{afi = AFI, address = Address,
					     mask_length = Mask},
			    source = Source},
			   nexthops = NHs, ifindexes = IFs, metric = Metric},
			  State) ->
    DstA = convert_addr(AFI, Address),
    {SourceM, SourceMaskM} = 
    	case Source of
    	    undefined -> {[], 0};
    	    #isis_prefix{address = SA, mask_length = SM} ->
    		{[{src, convert_addr(AFI, SA)}], SM}
    	end,
    SendMetric = trunc(Metric / State#state.metric_scale),
    lists:map(
      fun({NH, IF}) ->
	      NHA = convert_addr(AFI, NH),
	      Properties = [{dst, convert_addr(AFI, DstA)}, {gateway, NHA},
			    {oif, IF}, {priority, SendMetric}] ++ SourceM,
	      Msg = {case AFI of
			 ipv4 -> inet;
			 ipv6 -> inet6
		     end,
		     Mask, SourceMaskM, 0,
		     State#state.table,
		     State#state.protocol,
		     State#state.scope,
		     unicast, [],
		     Properties},
	      Req = #rtnetlink{type = newroute,
			       flags = [create, excl, ack],
			       seq = 0, pid = 0,
			       msg = Msg},
	      Result = netlink:request(rt, Req),
	      isis_logger:debug("Sent: ~p, Result: ~p", [Req, Result])
      end, lists:zip(NHs, IFs)),
    State.

delete_route_via_netlink(#isis_route_key
			 {prefix =
			      #isis_prefix{afi = AFI, address = Address,
					   mask_length = Mask},
			    source = Source},
			 State) ->
    DstA = convert_addr(AFI, Address),
    {SourceM, SourceMaskM} = 
    	case Source of
    	    undefined -> {[], 0};
    	    #isis_prefix{address = SA, mask_length = SM} ->
    		{[{src, convert_addr(AFI, SA)}], SM}
    	end,
    Properties = [{dst, convert_addr(AFI, DstA)}] ++ SourceM,
    Msg = {case AFI of
	       ipv4 -> inet;
	       ipv6 -> inet6
	   end,
	   Mask, SourceMaskM, 0,
	   State#state.table,
	   State#state.protocol,
	   State#state.scope,
	   unicast, [],
	   Properties},
    Req = #rtnetlink{type = delroute,
		     flags = [create, ack],
		     seq = 0, pid = 0,
		     msg = Msg},
    Result = netlink:request(rt, Req),
    isis_logger:debug("Sent: ~p, Result: ~p", [Req, Result]),
    State.

