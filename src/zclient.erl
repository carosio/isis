%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
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
-export([start_link/1, subscribe/1, unsubscribe/1]).

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
	  router_id :: [zclient_address()],
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
		   router_id = [],
		   listeners = dict:new()},
    io:format("State: ~p~n", [State]),
    %% Request services
    send_hello(State),
    request_router_id(State),
    request_interface(State),
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
    io:format("Adding ~p (~p)~n", [Name, Ifindex]),
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
    A = #zclient_address{afi = ipv4, address = Address,
			 mask_length = Mask},
    update_router_id(A, State);
handle_zclient_cmd(interface_address_add,
		   <<Ifindex:32, Flags:8, ?ZEBRA_AFI_IPV4:8,
		     Address:32, Mask:8, _Broadcast:32>>,
		   State) ->
    %% IPv4 Address
    I = dict:fetch(Ifindex, State#state.interfaces),
    A = #zclient_address{afi = ipv4, flags = Flags,
			 address = Address, mask_length = Mask},
    io:format("Adding address ~p to interface ~p~n", [A, I#zclient_interface.name]),
    update_interface_address(add, A, I, State);
handle_zclient_cmd(interface_address_add,
		   <<Ifindex:32, Flags:8, ?ZEBRA_AFI_IPV6:8,
		     Address:128, Mask:8, _Broadcast:128>>,
		   State) ->
    %% IPv6 address
    I = dict:fetch(Ifindex, State#state.interfaces),
    A = #zclient_address{afi = ipv6, flags = Flags,
			 address = Address, mask_length = Mask},
    io:format("Adding address ~p to interface ~p~n", [A, I#zclient_interface.name]),
    update_interface_address(add, A, I, State);
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
    update_listeners({add_address, I#zclient_interface.name, Address},
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
update_router_id(#zclient_address{afi = Afi} = Address, State) ->
    F = fun(A) when A#zclient_address.afi =:= Afi ->
		true;
	   (_) -> false
	end,
    NR = lists:filter(F, State#state.router_id),
    State#state{router_id = NR ++ [Address]}.

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
send_current_state(Pid, #state{interfaces = Interfaces}) ->
    I = dict:to_list(Interfaces),
    F = fun({_, A}) ->
		Z = A#zclient_interface{addresses = []},
		Pid ! {add_interface, Z},
		lists:map(fun(B) -> Pid ! {add_address, A#zclient_interface.name, B} end,
			  A#zclient_interface.addresses)
	end,
    lists:map(F, I).
				  
