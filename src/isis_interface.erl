%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% @end
%%% Created : 18 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_interface).

-behaviour(gen_server).

-include("isis_protocol.hrl").

-define(DEFAULT_INTERVAL, 10).
-define(SIOCGIFINDEX, 16#8933).
-define(SIOCGIFHWADDR, 16#8927).
-define(SIOCGIFMTU, 16#8921).

%% API
-export([start_link/1, send_packet/2, stop/1,
	 get_state/2, get_state/1, set/2]).

%% Debug export
-export([]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(ETH_P_802_2, 16#0400).

-record(state, {
	  name,            %% Interface name
	  ifindex,         %% Interface ifindex
	  socket,          %% Procket socket...
	  port,            %% Erlang port handling socket
	  system_ref,      %% Our 'IS-IS'
	  mac,             %% This interface's MAC address
	  mtu,             %% Interface MTU
	  hello_interval,  %% Hello interval
	  hold_time,       %% Hold time
	  timer,           %% Timer reference
	  adjacencies      %% Dict for SNPA -> FSM pid
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
send_packet(Pid, Packet) ->
    gen_server:call(Pid, {send_packet, Packet}).

stop(Pid) ->
    gen_server:cast(Pid, stop).

get_state(Pid, Item) ->
    gen_server:call(Pid, {get_state, Item}).

get_state(Pid) ->
    gen_server:call(Pid, {get_state}).

set(Pid, Values) ->
    gen_server:call(Pid, {set, Values}).

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
init([{Name, Ref}]) ->
    {Socket, Mac, Ifindex, MTU, Port} = create_port(Name),
    Timer = erlang:start_timer((?DEFAULT_INTERVAL * 1000), self(), trigger),
    State = #state{name = Name, socket = Socket, port = Port,
		   mac = Mac, mtu = MTU,
		   ifindex = Ifindex, system_ref = Ref,
		   hello_interval = ?DEFAULT_INTERVAL,
		   hold_time = (3 * ?DEFAULT_INTERVAL),
		   timer = Timer, adjacencies = dict:new()},
    send_iih(State),
    {ok, State}.

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
handle_call({send_packet, _Packet}, _From, State) ->
    {reply, ok, State};

handle_call({get_state, mac}, _From, State) ->
    {reply, State#state.mac, State};
handle_call({get_state, mtu}, _From, State) ->
    {reply, State#state.mtu, State};
handle_call({get_state, hello_interval}, _From, State) ->
    {reply, State#state.hello_interval, State};
handle_call({get_state, hold_time}, _From, State) ->
    {reply, State#state.hold_time, State};

handle_call({get_state}, _From, State) ->
    {reply, State, State};

handle_call({set, Values}, _From, State) ->
    NewState = set_values(Values, State),
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
handle_cast(stop, #state{port = Port,
			 adjacencies = Adjs,
			 timer = TimerRef} = State) ->
    %% Cancel our timer
    case TimerRef of
	undef -> undef;
	_ ->
	    erlang:cancel_timer(TimerRef)
    end,
    %% Close down the port (does this close the socket?)
    erlang:port_close(Port),
    %% Notify our adjacencies
    dict:map(fun(_Key, Pid) -> gen_fsm:send_event(Pid, stop) end,
	     Adjs),
    {stop, normal, State};

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
handle_info({_port, {data,
		     <<_To:6/binary, From:6/binary, _Len:16,
		       16#FE:8, 16#FE:8, 3:8, PDU/binary>>}},
	    State) ->
    NewState = 
	case isis_protocol:decode(PDU) of
	    {ok, DecodedPDU} ->
		handle_pdu(From, DecodedPDU, State);
	    _ ->
		io:format("Failed to decode: ~p~n", [PDU]),
		State
	end,
    {noreply, NewState};

handle_info({_port, {data, _}}, State) ->
    {noreply, State};

handle_info({timeout, _Ref, trigger}, State) ->
    erlang:cancel_timer(State#state.timer),
    send_iih(State),
    Timer = 
	erlang:start_timer((State#state.hello_interval * 1000),
			   self(), trigger),
    {noreply, State#state{timer = Timer}};

handle_info(Info, State) ->
    io:format("Unknown message: ~p", [Info]),
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

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handle an arriving PDU.
%%
%% @end
%%--------------------------------------------------------------------
-spec handle_pdu(binary(), isis_iih(), tuple()) -> tuple().
handle_pdu(From, #isis_iih{} = IIH,
	   #state{adjacencies = Adjs} = State) ->
    NewAdjs = 
	case dict:find(From, Adjs) of
	    {ok, Pid} ->
		gen_fsm:send_event(Pid, {iih, IIH}),
		Adjs;
	    _ ->
		{ok, NewPid} = isis_adjacency:start_link([{snpa, State#state.mac},
							  {interface, self()}]),
		gen_fsm:send_event(NewPid, {iih, IIH}),
		dict:store(From, NewPid, Adjs)
	end,
    State#state{adjacencies = NewAdjs};
handle_pdu(_, _, State) ->
    State.

-spec set_values(list(), tuple()) -> tuple().
set_values([{mtu, Value} | T], State) when is_integer(Value) ->
    set_values(T, State#state{mtu = Value});
set_values([{hello_interval, Value} | T], State) ->
    set_values(T, State#state{hello_interval = Value});
set_values([{mac, Binary} | T], State) ->
    set_values(T, State#state{mac = Binary});
set_values([], State) ->
    State.

-spec create_port(string()) -> {integer(), binary(), integer(), integer(), port()} | error.
create_port(Name) ->
    {ok, S} = procket:open(0,
			   [{progname, "sudo /usr/local/bin/procket"},
			    {family, packet},
			    {type, raw},
			    {protocol, ?ETH_P_802_2}]),
    {Ifindex, Mac, MTU} = interface_details(S, Name),
    LL = create_sockaddr_ll(Ifindex),
    ok = procket:bind(S, LL),
    Port = erlang:open_port({fd, S, S}, [binary, stream]),
    {S, Mac, Ifindex, MTU, Port}.

send_pdu(Pdu, Pdu_Size, State) ->
    Destination = <<1, 16#80, 16#C2, 0, 0, 16#15>>,
    Source = State#state.mac,
    Header = <<Destination/binary, Source/binary>>, 
    Len = Pdu_Size + 3,
    Packet = list_to_binary([Header, <<Len:16, 16#FE, 16#FE, 16#03>> | Pdu]),
    LL = create_sockaddr_ll(State#state.ifindex),
    Result = procket:sendto(State#state.socket, Packet, 0, LL),
    Result.

send_iih(State) ->
    IS_Neighbors =
	lists:map(fun({A, _}) -> A end,
		  dict:to_list(State#state.adjacencies)),
    IIH = #isis_iih{
	     pdu_type = level2_iih,
	     circuit_type = level_1_2,
	     source_id = <<255, 255, 0, 0, 3, 3>>,
	     holding_time = State#state.hold_time,
	     priority = 10,
	     dis = <<255, 255, 0, 0, 3, 3, 0>>,
	     tlv =
		 [
		  #isis_tlv_is_neighbors{neighbors = IS_Neighbors},
		  #isis_tlv_area_address{areas = [<<73, 0, 2>>]},
		  #isis_tlv_protocols_supported{protocols = [ipv4, ipv6]},
		  #isis_tlv_ip_interface_address{addresses = [3232298904]}
		 ]},
    {ok, PDU, PDU_Size} = isis_protocol:encode(IIH),
    send_pdu(PDU, PDU_Size, State).

-spec create_sockaddr_ll(integer()) -> binary().
create_sockaddr_ll(Ifindex) ->
    Family = procket:family(packet),
    <<Family:16/native, ?ETH_P_802_2:16/native, Ifindex:32/native,
      0:16, 0:8, 0:8, 0:8/unit:8>>.

%%
%% Linux specific, be nice to get this in the
%% procket module...
%%
interface_details(Socket, Name) ->
    N = list_to_binary(Name),
    Req = <<N/binary, 0:(8*(40 - byte_size(N)))>>,
    case procket:ioctl(Socket, ?SIOCGIFHWADDR, Req) of
	{error, _} -> error;
	{ok, Mac_Response} -> 
	    {ok, Ifindex_Response} = procket:ioctl(Socket,
						   ?SIOCGIFINDEX, Req),
	    {ok, MTU_Response} = procket:ioctl(Socket,
					       ?SIOCGIFMTU, Req),
	    <<_:16/binary, I:32/native, _/binary>> = Ifindex_Response,
	    <<_:18/binary, Mac:6/binary, _/binary>> = Mac_Response,
	    <<_:16/binary, MTU:16/native, _/binary>> = MTU_Response,
	    {I, Mac, MTU}
    end.
