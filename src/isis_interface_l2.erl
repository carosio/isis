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
%%% Created : 18 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_interface_l2).

-behaviour(gen_server).

-include("isis_system.hrl").
-include("isis_protocol.hrl").

-define(SIOCGIFMTU, 16#8921).
-define(SIOCGIFHWADDR, 16#8927).
-define(SIOCADDMULTI, 16#8931).
-define(SIOCGIFINDEX, 16#8933).

-define(BINARY_LIMIT, 5 * 1024 * 1024).    %% GC after 5MB of binarys have accumulated..

%% API
-export([start_link/1, stop/1,
	 send_pdu/4,
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
	  ifindex,         %% Ifindex
	  socket,          %% Procket socket...
	  port,            %% Erlang port handling socket
	  mac,             %% This interface's MAC address
	  mtu,             %% Interface MTU
	  interface_pid    %% Owning interface Pid - where we send rx-ed pdus
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
    gen_server:cast(Pid, {send_pdu, Pdu, Pdu_Size, Level}).

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
	{Socket, Mac, Ifindex, MTU, Port} ->
	    StartState = State#state{socket = Socket, port = Port,
				     mac = Mac, mtu = MTU,
				     ifindex = Ifindex
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
handle_call({get_mtu}, _From, #state{mtu = Mtu} = State) ->
    {reply, Mtu, State};

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
handle_cast({send_pdu, Pdu, Pdu_Size, Level}, State) ->
    Destination =
	case Level of 
	    level_1 -> <<1, 16#80, 16#C2, 0, 0, 16#14>>;
	    level_2 -> <<1, 16#80, 16#C2, 0, 0, 16#15>>
	end,
    Source = State#state.mac,
    Header = <<Destination/binary, Source/binary>>, 
    Len = Pdu_Size + 3,
    Packet = list_to_binary([Header, <<Len:16, 16#FE, 16#FE, 16#03>> | Pdu]),
    send_packet(Packet, State),
    {noreply, State};
handle_cast({send_pdu, _PDU, _PDU_Size, _}, State) ->
    {noreply, State};

handle_cast(stop, #state{port = Port} = State) ->
    %% Close down the port (does this close the socket?)
    erlang:port_close(Port),
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
		     <<_To:6/binary, From:6/binary, Len:16,
		       16#FE:8, 16#FE:8, 3:8, PDU/binary>> = B}},
	    State) ->
    NewState = 
	case (Len - 3) =< byte_size(PDU) of
	true ->
		Bytes = Len - 3,
		<<FinalPDU:Bytes/binary, _Tail/binary>> = PDU,
		case catch isis_protocol:decode(FinalPDU) of
		    {ok, DecodedPDU} ->
			isis_interface:received_pdu(State#state.interface_pid, From, DecodedPDU),
			State;
		    {'EXIT', Reason} ->
			isis_logger:error("Len: ~p B: ~p", [Len, B]),
			isis_logger:error("Failed to decode: ~p for ~p", [PDU, Reason]),
			State;
		    CatchAll ->
			isis_logger:error("Failed to decode: ~p", [CatchAll]),
			State
		end;
	    _ -> isis_logger:error("PDU received is shorter than size: ~p ~p", [Len, PDU]),
		 State
	end,
    {noreply, NewState};

handle_info({_port, {data, _}}, State) ->
    {noreply, State};

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
    isis_logger:debug("Unknown message: ~p", [Info]),
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
%%
%%
%% @end
%%--------------------------------------------------------------------
-spec create_port(string()) -> {integer(), binary(), integer(), integer(), port()} | error.
create_port(Name) ->
    case procket:open(0,
		      [{family, packet},
		       {type, raw},
		       {protocol, htons(?ETH_P_802_2)},
		       {interface, Name},
		       {isis}]) of
	{ok, S} ->
	    {Ifindex, Mac, MTU} = interface_details(S, Name),
	    LL = create_sockaddr_ll(Ifindex),
	    ok = procket:bind(S, LL),
	    Port = erlang:open_port({fd, S, S}, [binary, stream]),
	    {S, Mac, Ifindex, MTU, Port};
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
send_packet(Packet, State) ->
    LL = create_sockaddr_ll(State#state.ifindex),
    Result = procket:sendto(State#state.socket, Packet, 0, LL),
    Result.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------
-spec create_sockaddr_ll(integer()) -> binary().
create_sockaddr_ll(Ifindex) ->
    Family = procket:family(packet),
    <<Family:16/native, ?ETH_P_802_2:16, Ifindex:32/native,
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
	    <<_:16/binary, MTU:32/native, _/binary>> = MTU_Response,
	    %% Req2 = <<N/binary, 0:(8*(16 - byte_size(N))), I:16/native,
	    %%   	     16#01, 16#80, 16#c2, 0, 0, 16#14, 0:128>>,
	    %% Req3 = <<N/binary, 0:(8*(16 - byte_size(N))), I:16/native,
	    %% 	     16#01, 16#80, 16#c2, 0, 0, 16#15, 0:128>>,
	    %% {ok, _} = procket:ioctl(Socket, ?SIOCADDMULTI, Req2),
	    %% {ok, _} = procket:ioctl(Socket, ?SIOCADDMULTI, Req3),
	    {I, Mac, MTU}
    end.


extract_args([{name, Name} | T], State) ->
    extract_args(T, State#state{name = Name});
extract_args([{interface_pid, Pid} | T], State) ->
    extract_args(T, State#state{interface_pid = Pid});
extract_args([], State) ->
    State.

