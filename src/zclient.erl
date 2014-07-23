%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% ZClient interface
%%%
%%% @end
%%% Created : 21 Feb 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(zclient).

-behaviour(gen_server).

-include ("zclient.hrl").

%% API
-export([start_link/1,
	 %% Subscription to updates...
	 subscribe/1, unsubscribe/1,
	 %% Sending information to the RIB
	 add/1, delete/1, request_redist/1,
	 get_redistributed_routes/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
	  route_type :: atom(),
	  zsock :: port(),
	  zhead :: zclient_header(),
	  buffer,
	  %% State for zclient
	  interfaces :: dict(),          %% Map ifindex->record
	  routes :: dict(),              %% Map prefix -> record
	  router_id :: [zclient_prefix()],
	  %% State for listeners
	  listeners :: dict()
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

add(#zclient_route{} = Route) ->
    gen_server:call(?MODULE, {send_route, Route});
add(Unknown) ->
    lager:error("zclient:add called with unknown argument ~p", [Unknown]),
    unknown.

delete(#zclient_route_key{} = RouteKey) ->
    gen_server:call(?MODULE, {delete_route, RouteKey});
delete(Unknown) ->
    lager:error("zclient:delete called with unknown argument ~p", [Unknown]),
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
init([{type, T}]) ->
    {ok, ZSock} = gen_tcp:connect("localhost", 2600,
				  [binary, {packet, 0}]),
    State = #state{zsock = ZSock, route_type = T, buffer = <<>>,
		   zhead = #zclient_header{command = unknown},
		   interfaces = dict:new(),
		   routes = dict:new(),
		   router_id = [],
		   listeners = dict:new()},
    %% Request services
    send_hello(State),
    request_router_id(State),
    request_interface(State),
    erlang:start_timer(1000, self(), request_redist),
    %%request_redistribution(static, State),
    %%request_redistribution(kernel, State),
    {ok, State};
init(Args) ->
    io:format("Unknown args: ~p~n", [Args]),
    {stop, fuckedup}.

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
    %% Monitor the subscribing process, so we know if they die
    erlang:monitor(process, Pid),
    send_current_state(Pid, State),
    {reply, ok, State#state{listeners = dict:store(Pid, [], Clients)}};

handle_call({unsubscribe, Pid}, _From, State) ->
    NewState = remove_client(Pid, State),
    {reply, ok, NewState};
handle_call({send_route, Route}, _From, State) ->
    send_route(Route, State),
    {reply, ok, State};
handle_call({delete_route, RouteKey}, _From, State) ->
    delete_route(RouteKey, State),
    {reply, ok, State};
handle_call({request_redist, Type}, _From, State) ->
    request_redistribution(Type, State),
    {reply, ok, State};
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
handle_info({tcp, _Socket, Data}, #state{buffer = Buffer} = State) ->
    NewBuffer = <<Buffer/binary, Data/binary>>,
    NewState = handle_zclient_msg(NewBuffer, State),
    {noreply, NewState};
handle_info({'DOWN', _Ref, process, Pid2, _Reason}, State) ->
    NewState = remove_client(Pid2, State),    
    {noreply, NewState};
handle_info({timeout, _Ref, request_redist}, State) ->
    request_redistribution(static, State),
    request_redistribution(kernel, State),
    {noreply, State};
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
send_hello(State) ->
    T = zclient_enum:to_int(zebra_route, State#state.route_type),
    Body = <<T:8>>,
    Message = create_header(hello, Body),
    send_message(Message, State).

%%--------------------------------------------------------------------
%% @doc Subscribe to router_id updates
%% @end
%%--------------------------------------------------------------------
request_router_id(State) ->
    Message = create_header(router_id_add, <<>>),
    send_message(Message, State).

%%--------------------------------------------------------------------
%% @doc Subscribe to interface updates
%% @end
%%--------------------------------------------------------------------
request_interface(State) ->
    Message = create_header(interface_add, <<>>),
    send_message(Message, State).

%%--------------------------------------------------------------------
%% @doc Request redistribution
%% @end
%%--------------------------------------------------------------------
request_redistribution(Route, State) ->
    R = zclient_enum:to_int(zebra_route, Route),
    Message = create_header(redistribute_add, <<R:8>>),
    send_message(Message, State).

%%--------------------------------------------------------------------
%% @doc Create the basic zclient header for a message
%% @end
%%--------------------------------------------------------------------
create_header(Command, Body) ->
    C = zclient_enum:to_int(zclient_command, Command),
    Len = byte_size(Body) + ?ZEBRA_HEADER_SIZE,
    <<Len:16,
      ?ZEBRA_HEADER_MARKER:8,
      ?ZSERV_VERSION:8,
      C:16,
      Body/binary>>.

%%--------------------------------------------------------------------
%% @doc Send message to the zebra daemon
%% @end
%%--------------------------------------------------------------------
send_message(M, State) ->
    gen_tcp:send(State#state.zsock, M).

%%--------------------------------------------------------------------
%% @doc Multi-clause function to process an incoming message from the
%% zebra daemon. Messages are parsed and internal state is update. We
%% also notify listeners about the state update.
%% @end
%% --------------------------------------------------------------------
-spec handle_zclient_msg(binary(), #state{}) -> #state{}.
handle_zclient_msg(<<Len:16, ?ZEBRA_HEADER_MARKER:8,
		     ?ZSERV_VERSION:8, Command:16, Rest/binary>>,
		       #state{zhead = #zclient_header{command = unknown}} = State) ->
    C = zclient_enum:to_atom(zclient_command, Command),
    handle_zclient_msg(Rest, State#state{zhead = #zclient_header{length = Len - ?ZEBRA_HEADER_SIZE,
								 command = C}});
handle_zclient_msg(Buffer,
		   #state{zhead = #zclient_header{length = Len, command = C}} = State)
  when byte_size(Buffer) >= Len ->
    <<M:Len/binary, Rest/binary>> = Buffer,
    NewState = handle_zclient_cmd(C, M, State),
    handle_zclient_msg(Rest, NewState#state{zhead = #zclient_header{command = unknown}});
handle_zclient_msg(Buffer, State) ->
    State#state{buffer = Buffer}.

handle_zclient_cmd(interface_add,
		   <<N:20/binary, Ifindex:32, Status:8, Flags:64, Metric:32,
		     Mtu:32, Mtu6:32, Bandwidth:32, HwLen:32, Mac:HwLen/binary>>,
		   State) ->
    N1 = binary_to_list(N),
    Name = string:left(N1, string:chr(N1, 0)-1),
    I = #zclient_interface{
	   name = Name, ifindex = Ifindex,
	   status = Status, flags = Flags,
	   metric = Metric, mtu = Mtu,
	   mtu6 = Mtu6, bandwidth = Bandwidth,
	   mac = Mac, addresses = []
	  },
    update_listeners({add_interface, I}, State),
    NewInterfaces = dict:store(Ifindex, I, State#state.interfaces),
    State#state{interfaces = NewInterfaces};
handle_zclient_cmd(interface_up,
		   <<N:20/binary, Ifindex:32, Status:8, Flags:64, Metric:32,
		     Mtu:32, Mtu6:32, Bandwidth:32, HwLen:32, Mac:HwLen/binary>>,
		   State) ->
    N1 = binary_to_list(N),
    Name = string:left(N1, string:chr(N1, 0)-1),
    I = #zclient_interface{
	   name = Name, ifindex = Ifindex,
	   status = Status, flags = Flags,
	   metric = Metric, mtu = Mtu,
	   mtu6 = Mtu6, bandwidth = Bandwidth,
	   mac = Mac
	  },
    io:format("Adding ~p (~p)~n", [Name, Ifindex]),
    update_listeners({add_interface, I}, State),
    NewInterfaces = dict:store(Ifindex, I, State#state.interfaces),
    State#state{interfaces = NewInterfaces};    
handle_zclient_cmd(router_id_update,
		   <<?ZEBRA_AFI_IPV4:8, Address:32, Mask:8>>,
		   State) ->
    A = #zclient_prefix{afi = ipv4, address = Address,
			 mask_length = Mask},
    update_router_id(A, State);
handle_zclient_cmd(interface_address_add,
		   <<Ifindex:32, Flags:8, ?ZEBRA_AFI_IPV4:8,
		     Address:32, Mask:8, _Broadcast:32>>,
		   State) ->
    %% IPv4 Address
    I = dict:fetch(Ifindex, State#state.interfaces),
    A = #zclient_prefix{afi = ipv4, flags = Flags,
			 address = Address, mask_length = Mask},
    io:format("Adding address ~s/~p to interface ~p~n",
	      [isis_system:address_to_string(ipv4, Address), Mask, I#zclient_interface.name]),
    update_interface_address(add, A, I, State);
handle_zclient_cmd(interface_address_add,
		   <<Ifindex:32, Flags:8, ?ZEBRA_AFI_IPV6:8,
		     Address:128, Mask:8, _Broadcast:128>>,
		   State) ->
    %% IPv6 address
    I = dict:fetch(Ifindex, State#state.interfaces),
    A = #zclient_prefix{afi = ipv6, flags = Flags,
			address = Address, mask_length = Mask},
    io:format("Adding address ~s/~p to interface ~p~n",
	      [isis_system:address_to_string(ipv6, Address), Mask, I#zclient_interface.name]),
    update_interface_address(add, A, I, State);
handle_zclient_cmd(interface_address_delete,
		   <<Ifindex:32, Flags:8, ?ZEBRA_AFI_IPV4:8,
		     Address:32, Mask:8, _Broadcast:32>>,
		   State) ->
    %% IPv4 Address
    I = dict:fetch(Ifindex, State#state.interfaces),
    A = #zclient_prefix{afi = ipv4, flags = Flags,
			 address = Address, mask_length = Mask},
    io:format("Deleting address ~p to interface ~p~n", [A, I#zclient_interface.name]),
    update_interface_address(del, A, I, State);
handle_zclient_cmd(interface_address_delete,
		   <<Ifindex:32, Flags:8, ?ZEBRA_AFI_IPV6:8,
		     Address:128, Mask:8, _Broadcast:128>>,
		   State) ->
    %% IPv6 address
    I = dict:fetch(Ifindex, State#state.interfaces),
    A = #zclient_prefix{afi = ipv6, flags = Flags,
			address = Address, mask_length = Mask},
    io:format("Deleting address ~p to interface ~p~n", [A, I#zclient_interface.name]),
    update_interface_address(del, A, I, State);
handle_zclient_cmd(ipv4_route_add,
		   <<Type:8, Flags:8, Info:8, Mask:8, R0/binary>>,
		   State) ->
    io:format("Type: ~p, Flags: ~p, Info: ~p~n", [Type, Flags, Info]),
    R = read_ipv4_route(Type, Flags, Info, Mask, R0),
    NewRoutes = dict:store({R#zclient_route.route,
			    R#zclient_route.nexthops},
			   R, State#state.routes),
    update_listeners({redistribute_add, R}, State),
    State#state{routes = NewRoutes};
handle_zclient_cmd(ipv4_route_delete,
		   <<Type:8, Flags:8, Info:8, Mask:8, R0/binary>>,
		   State) ->
    R = read_ipv4_route(Type, Flags, Info, Mask, R0),
    NewRoutes = dict:erase({R#zclient_route.route,
			    R#zclient_route.nexthops}, State#state.routes),
    update_listeners({redistribute_delete, R}, State),
    State#state{routes = NewRoutes};
handle_zclient_cmd(ipv6_route_add,
		   <<Type:8, Flags:8, Info:8, Mask:8, R0/binary>>,
		   State) ->
    R = read_ipv6_route(Type, Flags, Info, Mask, R0),
    NewRoutes = dict:store({R#zclient_route.route,
			    R#zclient_route.nexthops},
			   R, State#state.routes),
    update_listeners({redistribute_add, R}, State),
    State#state{routes = NewRoutes};
handle_zclient_cmd(ipv6_route_delete,
		   <<Type:8, Flags:8, Info:8, Mask:8, R0/binary>>,
		   State) ->
    R = read_ipv6_route(Type, Flags, Info, Mask, R0),
    NewRoutes = dict:erase({R#zclient_route.route,
			    R#zclient_route.nexthops}, State#state.routes),
    update_listeners({redistribute_delete, R}, State),
    State#state{routes = NewRoutes};
handle_zclient_cmd(C, M, State) ->
    io:format("Handling unknown command ~p (~p)~n", [C, M]),
    State.

%%--------------------------------------------------------------------
%% @doc
%% @end
%% --------------------------------------------------------------------
update_interface_address(AddDel, Address,
			 #zclient_interface{addresses = A} = Interface,
			 State) ->
    L = add_or_update_address(AddDel, Address, A),
    I = Interface#zclient_interface{addresses = L},
    D = dict:store(I#zclient_interface.ifindex, I,
		   State#state.interfaces),
    Action = case AddDel of
		 add -> add_address;
		 del -> del_address
	     end,
    update_listeners({Action, I#zclient_interface.name, Address},
		     State),
    State#state{interfaces = D}.

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
%% @doc We have 1 Router-ID per AFI, so we remove the old ID for this
%% AFI and replace with this one.
%% @end
%% --------------------------------------------------------------------
update_router_id(#zclient_prefix{afi = Afi} = Address, State) ->
    F = fun(A) when A#zclient_prefix.afi =:= Afi ->
		false;
	   (_) -> true
	end,
    NR = lists:filter(F, State#state.router_id),
    update_listeners({router_id, Address}, State),
    State#state{router_id = NR ++ [Address]}.

read_ipv4_route(_Type, _Flags, Info, MaskLen, R0) ->
    <<_:3, SrcPfxFlag:1, MetricFlag:1, DistanceFlag:1, IfindexFlag:1,
      NexthopFlag:1>> = <<Info:8>>,
    ASize = erlang:trunc((MaskLen+7)/8) * 8,
    <<A:ASize, R1/binary>> = R0,
    Address = A bsl (32 - ASize),
    {SrcPfx, R6} = 
	case SrcPfxFlag of
	    1 -> <<SrcPfxLen:8, R6T/binary>> = R1,
		 SrcPfxBits = erlang:trunc((SrcPfxLen+7)/8) * 8,
		 <<SrcPfxB:SrcPfxBits, R6T2/binary>> = R6T,
		 {#zclient_prefix{afi = ipv4,
				  address = SrcPfxB bsl (32 - SrcPfxBits),
				  mask_length = SrcPfxLen},
		  R6T2};
	    0 -> {undefined, R1}
	end,
    {Nexthop, R2} =
	case NexthopFlag of
	    1 -> <<NextHopNum:8, R2T1/binary>> = R6,
		 NexthopBytes = NextHopNum * 4,
		 <<Nexthops:NexthopBytes/binary, R2T2/binary>> = R2T1,
		 {[N || <<N:32>> <= Nexthops], R2T2};
	    _ -> {0, R6}
	end,
    {Ifindex, R3} =
	case IfindexFlag of
	    1 -> <<Ifindexnum:8, R3T1/binary>> = R2,
		 IfBytes = Ifindexnum * 4,
		 <<IfIndexes:IfBytes/binary, R3T2/binary>> = R3T1,
		 {[I || <<I:32>> <= IfIndexes], R3T2};
	    _ -> {0, R2}
	end,
    {Distance, R4} = 
	case DistanceFlag of
	    1 -> <<DistanceT:8, R4T/binary>> = R3,
		 {DistanceT, R4T};
	    _ -> {0, R3}
	end,
    {Metric, _R5} =
	case MetricFlag of
	    1 -> <<MetricT:32, R5T/binary>> = R4,
		 {MetricT, R5T};
	    _ -> {0, R4}
	end,
    P = #zclient_prefix{afi = ipv4, address = Address, mask_length = MaskLen},
    K = #zclient_route_key{prefix = P, source = SrcPfx},
    R = #zclient_route{route = K,
		       nexthops = Nexthop,
		       ifindexes = Ifindex,
		       metric = Metric},
    R.

read_ipv6_route(_Type, _Flags, Info, MaskLen, R0) ->
    <<_:3, SrcPfxFlag:1, MetricFlag:1, DistanceFlag:1, IfindexFlag:1,
      NexthopFlag:1>> = <<Info:8>>,
    ASize = erlang:trunc((MaskLen+7)/8) * 8,
    <<A:ASize, R1/binary>> = R0,
    Address = A bsl (128 - MaskLen),
    {SrcPfx, R6} = 
	case SrcPfxFlag of
	    1 -> <<SrcPfxLen:8, R6T/binary>> = R1,
		 SrcPfxBytes = erlang:trunc((SrcPfxLen+7)/8),
		 <<SrcPfxB:SrcPfxBytes/binary, R6T2/binary>> = R6T,
		 {#zclient_prefix{afi = ipv6,
				  address = SrcPfxB,
				  mask_length = SrcPfxLen},
		  R6T2};
	    0 -> {undefined, R1}
	end,
    {Nexthop, R2} =
	case NexthopFlag of
	    1 -> <<NextHopNum:8, R2T1/binary>> = R6,
		 NexthopBytes = NextHopNum * 16,
		 <<Nexthops:NexthopBytes/binary, R2T2/binary>> = R2T1,
		 {[N || <<N:128>> <= Nexthops], R2T2};
	    _ -> {0, R6}
	end,
    {Ifindex, R3} =
	case IfindexFlag of
	    1 -> <<Ifindexnum:8, R3T1/binary>> = R2,
		 IfBytes = Ifindexnum * 4,
		 <<IfIndexes:IfBytes/binary, R3T2/binary>> = R3T1,
		 {[I || <<I:32>> <= IfIndexes], R3T2};
	    _ -> {0, R2}
	end,
    {Distance, R4} = 
	case DistanceFlag of
	    1 -> <<DistanceT:8, R4T/binary>> = R3,
		 {DistanceT, R4T};
	    _ -> {0, R3}
	end,
    {Metric, _R5} =
	case MetricFlag of
	    1 -> <<MetricT:32, R5T/binary>> = R4,
		 {MetricT, R5T};
	    _ -> {0, R4}
	end,
    P = #zclient_prefix{afi = ipv6, address = Address, mask_length = MaskLen},
    K = #zclient_route_key{prefix = P, source = SrcPfx},
    R = #zclient_route{route = K,
		       nexthops = Nexthop,
		       ifindexes = Ifindex,
		       metric = Metric},
    R.

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
send_current_state(Pid, #state{router_id = RouterIDs,
			       interfaces = Interfaces}) ->
    %% Send router-id
    RF = fun(RI) -> Pid ! {router_id, RI} end,
    lists:map(RF, RouterIDs),

    %% Now send interface information
    I = dict:to_list(Interfaces),
    F = fun({_, A}) ->
		Z = A#zclient_interface{addresses = []},
		Pid ! {add_interface, Z},
		lists:map(fun(B) -> Pid ! {add_address, A#zclient_interface.name, B} end,
			  A#zclient_interface.addresses)
	end,
    lists:map(F, I).
				  
send_route(#zclient_route{route =
			      #zclient_route_key{prefix = 
						     #zclient_prefix{afi = AFI, address = Address,
								     mask_length = Mask},
						 source = Source},
			  nexthops = NH, ifindexes = IFs, metric = Metric},
	   State) ->
    Type = zclient_enum:to_int(zebra_route, isis),
    Unicast = zclient_enum:to_int(safi, unicast),
    NHBin =
	case AFI of
	    ipv4 ->
		NHT = zclient_enum:to_int(nexthop, ipv4_ifindex),
		Count = length(NH),
		NHB = << <<NHT:8, G:32, I:32>> || {G, I} <- lists:zip(NH, IFs) >>,
		<<Count:8, NHB/binary>>;
	    ipv6 ->
		NHT1 = zclient_enum:to_int(nexthop, ipv6),
		NHT2 = zclient_enum:to_int(nexthop, ifindex),
		HCount  = length(NH) * 2,
		NHB = << <<NHT1:8, G/binary, NHT2:8, I:32>> || {G,I} <- lists:zip(NH, IFs) >>,
		<<HCount:8, NHB/binary>>
	end,
    {SrcPresent, SrcBin} =
	case Source of
	    #zclient_prefix{address = SDA, mask_length = M} ->
		{1, <<M:8, SDA/binary>>};
	    _ -> {0, <<>>}
	end,
    ASize = erlang:trunc((Mask+7)/8) * 8,
    A = 
	case AFI of
	    ipv4 -> Address bsr (32 - ASize);
	    ipv6 -> 
		case is_binary(Address) of
		    true -> <<I:ASize>> = Address,
			    I;
		    _ -> Address bsr (128 - ASize)
		end
	end,
    RouteMessage = 
	<<Type:8,
	  0:8, %% 'Flags'
	  0:3, %% unused
          SrcPresent:1,
	  1:1, %% Metric present
	  1:1, %% Distance present
	  0:1, %% Ifindex present (unused)
	  1:1, %% Nexthop present
	  Unicast:16,
	  Mask:8,
	  A:ASize,
	  SrcBin/binary,
	  NHBin/binary,
	  115:8, %% Distance..
	  Metric:32>>,
    MessageType
	= case AFI of
	      ipv4 -> ipv4_route_add;
	      ipv6 -> ipv6_route_add
	  end,
    Message = create_header(MessageType, RouteMessage),
    send_message(Message, State).

delete_route(#zclient_route_key{
		prefix = 
		    #zclient_prefix{afi = AFI, address = Address,
				    mask_length = Mask},
		source = Source},
	     State) ->
    Type = zclient_enum:to_int(zebra_route, isis),
    Unicast = zclient_enum:to_int(safi, unicast),
    ASize = erlang:trunc((Mask+7)/8) * 8,
    ABin = case AFI of
	       ipv4 -> A = Address bsr (32 - ASize),
		       <<A:ASize>>;
	       ipv6 -> case is_binary(Address) of
			   true -> Address;
			   _ -> A = Address bsr (128 - ASize),
				<<A:ASize>>
		       end
	   end,
    {SourcePresent, SourceBin} = 
	case Source of
	    undefined -> {0, <<>>};
	    #zclient_prefix{address = SAddress,
			    mask_length = SMask} ->
		{1, <<SMask:8, SAddress/binary>>}
	end,
    RouteMessage = 
	<<Type:8,
	  0:8, %% Flags(unused)
	  0:3,
	  SourcePresent:1,
	  0:4,
	  Unicast:16,
	  Mask:8,
	  ABin/binary,
	  SourceBin/binary>>,
    MessageType
	= case AFI of
	      ipv4 -> ipv4_route_delete;
	      ipv6 -> ipv6_route_delete
	  end,
    Message = create_header(MessageType, RouteMessage),
    send_message(Message, State).
