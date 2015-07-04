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
%%% Created : 27 May 2015 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_interface_l3).

-behaviour(gen_server).

-include("isis_system.hrl").
-include("isis_protocol.hrl").

%% This is a bit nasty...
-define(ISIS_L3_PROTOCOL, 124).
-define(AF_INET6, 10).
-define(IPPROTO_IPV6, 41).
-define(IPV6_RECVPKTINFO, 49).    %% int
-define(IPV6_UNICAST_HOPS, 16).   %% int
-define(IPV6_MULTICAST_HOPS, 18). %% int
-define(IPV6_MULTICAST_LOOP, 19). %% int
-define(IPV6_JOIN_GROUP, 20).     %% struct ipv6_mreq {in6_addr, int}
-define(SIOCGIFMTU, 16#8921).
-define(SIOCGIFHWADDR, 16#8927).
-define(SIOCGIFINDEX, 16#8933).
-define(SOL_SOCKET, 1).
-define(SO_REUSEADDR, 2).

-define(IPV6_ALL_L1_IS, "ff02::db8:1515:1").
-define(IPV6_ALL_L2_IS, "ff02::db8:1515:2").

%% Christian's document suggests 1280...
-define(ISIS_MAX_L3_MESSAGE_SIZE, 1500).

-define(BINARY_LIMIT, 5 * 1024 * 1024).    %% GC after 5MB of binarys have accumulated..

%% API
-export([start_link/1, stop/1,
	 send_pdu/4, send_pdu_to/4,
	 get_mtu/1, get_mac/1
	]).

%% Debug export
-export([]).
-compile(export_all).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(ETH_P_802_2, 16#0004).

-record(state, {
	  name,            %% Interface Name
	  mode = broadcast,%% broadcast, point_to_point or point_to_multipoint
	  ifindex,         %% Ifindex
	  socket,          %% Procket socket...
	  port,            %% Erlang port handling socket
	  mac,             %% This interface's MAC address
	  mtu,             %% Interface MTU
	  interface_pid,   %% Owning interface Pid - where we send rx-ed pdus
	  receive_pid      %% Pid of our 'receive' process...
	 }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link(list()) -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
send_pdu(Pid, Pdu, Pdu_Size, Level) ->
    gen_server:cast(Pid, {send_pdu, undefined, Pdu, Pdu_Size, Level}).

send_pdu_to(Pid, To, Pdu, Pdu_Size) ->
    gen_server:cast(Pid, {send_pdu, To, Pdu, Pdu_Size, undefined}).

stop(Pid) ->
    gen_server:cast(Pid, stop).

get_mtu(Pid) ->
    gen_server:call(Pid, {get_mtu}).

get_mac(Pid) ->
    gen_server:call(Pid, {get_mac}).


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
init(Args) ->
    process_flag(trap_exit, true),
    State = extract_args(Args, #state{}),
    isis_logger:debug("Creating socket for interface ~p (~p)", [State#state.name, State]),
    case create_port(State#state.name) of
	{Socket, Mac, Ifindex, MTU, _} ->
	    {ok, ReceivePid} = start_receiver(Socket, self()),
	    StartState = State#state{socket = Socket,
				     mac = Mac, mtu = MTU,
				     ifindex = Ifindex,
				     receive_pid = ReceivePid
				    },
	    erlang:send_after(60 * 1000, self(), {gc}),
	    {ok, StartState};
	error ->
	    {stop, no_socket}
    end.

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
handle_call({get_mac}, _From, #state{mac = Mac} = State) ->
    {reply, Mac, State};
handle_call({get_mtu}, _From, State) ->
    %% Hardcode our MTU for now, to match the Quagga sizing..
    {reply, 1243, State};

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
handle_cast({send_pdu, undefined, Pdu, _Pdu_Size, Level}, State) ->
    Packet = list_to_binary(Pdu),
    send_packet(Packet, Level, State),
    {noreply, State};
handle_cast({send_pdu, {ipv6, To}, Pdu, _Pdu_Size, _Level}, State) ->
    Packet = list_to_binary(Pdu),
    send_packet_to(To, Packet, State),
    {noreply, State};

handle_cast(stop, State) ->
    %% Close down the port (does this close the socket?)
    %% erlang:port_close(Port),
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
handle_info({message, PDU, From}, State) ->
    %% We need the packet details from PKTINFO... ugh..
    MappedFrom = 
	case State#state.mode of
	    broadcast -> snpa_from_ipv6(From);
	    point_to_multipoint -> From
	end,
    NewState = 
	case catch isis_protocol:decode(PDU) of
	    {ok, DecodedPDU} ->
		isis_interface:received_pdu(State#state.interface_pid, MappedFrom, DecodedPDU),
		State;
	    {'EXIT', Reason} ->
		isis_logger:error("Failed to decode: ~p for ~p", [PDU, Reason]),
		State;
	    CatchAll ->
		isis_logger:error("Failed to decode: ~p", [CatchAll]),
		State
	end,
    {noreply, NewState};

handle_info({gc}, State) ->
    case erlang:memory(binary) of
	Binary when Binary > ?BINARY_LIMIT ->
	    isis_logger:debug("Forcing garbage collection..."),
	    erlang:garbage_collect(self());
	_ ->
	    ok
    end,
    erlang:send_after(60 * 1000, self(), {gc}),
    {noreply, State};

handle_info({'EXIT', Pid, normal}, State)
  when Pid =:= State#state.interface_pid ->
    {stop, no_interface, State};
handle_info({'EXIT', _Pid, normal}, State) ->
    {noreply, State};

handle_info(Info, State) ->
    isis_logger:error("Unknown message: ~p", [Info]),
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
%% 
%% Handle the various PDUs that we can receive on this interface
%%
%% @end
%%--------------------------------------------------------------------


%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Turn on a level
%%
%% @end
%%--------------------------------------------------------------------


%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------
-spec set_values(list(), tuple()) -> tuple().
set_values([{mtu, Value} | T], State) when is_integer(Value) ->
    set_values(T, State#state{mtu = Value});
set_values([{mac, Binary} | T], State) ->
    set_values(T, State#state{mac = Binary});
set_values([], State) ->
    State.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%%
%%
%% @end
%%--------------------------------------------------------------------
-spec htons(integer()) -> integer().
htons(I) ->
	<<HI:16/native>> = <<I:16>>,
	HI.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% This is the sender socket. It looks like we need a receive socket
%% run from somewhere that can do recvmsg and get the packet header info...
%%
%% @end
%%--------------------------------------------------------------------
-spec create_port(string()) -> {integer(), binary(), integer(), integer(), port()} | error.
create_port(Name) ->
    case procket:open(0,
		      [{family, ?AF_INET6},
		       {type, raw},
		       {protocol, ?ISIS_L3_PROTOCOL},
		       {interface, Name}]) of
	{ok, S} ->
	    ok = procket:setsockopt(S, ?SOL_SOCKET, ?SO_REUSEADDR, <<1:32/native>>),
	    ok = procket:setsockopt(S, ?IPPROTO_IPV6, ?IPV6_RECVPKTINFO, <<1:32/native>>),
	    ok = procket:setsockopt(S, ?IPPROTO_IPV6, ?IPV6_MULTICAST_LOOP, <<0:32/native>>),
	    ok = procket:setsockopt(S, ?IPPROTO_IPV6, ?IPV6_MULTICAST_HOPS, <<1:32/native>>),
	    ok = procket:setsockopt(S, ?IPPROTO_IPV6, ?IPV6_UNICAST_HOPS, <<1:32/native>>),

	    {Ifindex, Mac, MTU} = interface_details(S, Name),

	    %% Now join the 2 groups...
	    ok = join_group(S, Ifindex, ?IPV6_ALL_L1_IS),
	    ok = join_group(S, Ifindex, ?IPV6_ALL_L2_IS),
	    
	    %% LL = create_sockaddr_ll(Ifindex),
	    %% ok = procket:bind(S, LL),
	    %% Port = erlang:open_port({fd, S, S}, [binary]),

	    isis_logger:debug("Opened L3 socket: ~p", [S]),

	    {S, Mac, Ifindex, MTU, undefined};
	{error, einval} ->
	    isis_logger:error("Failed to create socket for ~s", [Name]),
	    error
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------
send_packet(Packet, Level, State) ->
    LL = create_sockaddr_ll(Level, State#state.ifindex),
    Result = procket:sendto(State#state.socket, Packet, 0, LL),
    Result.

send_packet_to(To, Packet, State) ->
    DestAddr = create_sockaddr(To, State#state.ifindex),
    Result = procket:sendto(State#state.socket, Packet, 0, DestAddr),
    Result.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------
create_sockaddr_ll(Level, Ifindex) ->
    {ok, Addr} =
	case Level of
	    level_1 ->
		inet:parse_address(?IPV6_ALL_L1_IS);
	    level_2 ->
		inet:parse_address(?IPV6_ALL_L2_IS)
	end,
    BinAddr = << <<A:16>> || A <- erlang:tuple_to_list(Addr) >>,
    <<(?AF_INET6):16/native,
      0:16,  %% sin_port (__be16)
      0:32,  %% sin_flowinfo (__be32)
      BinAddr/binary,
      Ifindex:32/native>>.

create_sockaddr(To, Ifindex) ->
    BinAddr = << <<A:16>> || A <- erlang:tuple_to_list(To) >>,
    <<(?AF_INET6):16/native,
      0:16,  %% sin_port (__be16)
      0:32,  %% sin_flowinfo (__be32)
      BinAddr/binary,
      Ifindex:32/native>>.

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
	    <<_:16/binary, MTU:32/native, _/binary>> = MTU_Response,
	    {I, Mac, MTU}
    end.

extract_args([{name, Name} | T], State) ->
    extract_args(T, State#state{name = Name});
extract_args([{interface_pid, Pid} | T], State) ->
    extract_args(T, State#state{interface_pid = Pid});
extract_args([{mode, broadcast} | T], State) ->
    extract_args(T, State#state{mode = broadcast});
extract_args([{mode, point_to_multipoint} | T], State) ->
    extract_args(T, State#state{mode = point_to_multipoint});
extract_args([], State) ->
    State.

join_group(Socket, IfIndex, Address) ->
    {ok, Addr} = inet:parse_address(Address),
    BinAddr = << <<A:16>> || A <- erlang:tuple_to_list(Addr) >>,
    procket:setsockopt(Socket, ?IPPROTO_IPV6,
		       ?IPV6_JOIN_GROUP,
		       <<BinAddr/binary, IfIndex:32/native>>).

do_receive(Socket, Parent) ->
    case gen_udp:recv(Socket, ?ISIS_MAX_L3_MESSAGE_SIZE) of
	{ok, {From, _, Packet}} ->
	    Parent ! {message, Packet, {ipv6, From}},
	    do_receive(Socket, Parent);
	Other ->
	    isis_logger:error("Received: ~p", [Other]),
	    exit(self(), normal)
    end.

start_receiver(Socket, Pid) ->
    case gen_udp:open(0, [binary, {fd, Socket}, {active, false}, inet6]) of
	{ok, S} ->
	    F = fun() -> do_receive(S, Pid) end,
	    {ok, erlang:spawn(F)};
	{error, Reason} ->
	    isis_logger:error("Failed to start receiver: ~p", [Reason]),
	    error
    end.

%% Based on the code from Christian...
snpa_from_ipv6({ipv6, Address}) ->
    BinAddr =
	<< <<X:16>> || X <- erlang:tuple_to_list(Address) >>,
    <<_:(8*8), A:8, B:16, T:16, D:24>> = BinAddr,
    %% If bytes 11 & 12 are not 0xFFFE then we may have an issue...
    case T =:= 65534 of
	false ->
	    isis_logger:warn("IPv5 address is not EUI-48 derived, conflicts may occur");
	_ ->
	    ok
    end,
    %% Xor locally administered bit...
    <<(A bxor 2):8, B:16, D:24>>.
