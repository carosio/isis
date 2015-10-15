%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2015, Alistair Woodman, California USA <awoodman@netdef.org>
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
%%% Created : 30 Aug 2015 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_config_pipe).
-author('Rick Payne <rickp@rossfell.co.uk>').

-behaviour(gen_server).

-include("isis_system.hrl").

-define(CONFIG_PIPE, "/tmp/autoisis_config").

%% API
-export([start_link/0, start_receiver/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
	  fifo = undefined
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

start_receiver() ->
    gen_server:cast(?MODULE, {start_receiver}).

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
    {ok, #state{}}.

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
handle_cast({start_receiver}, State) ->
    Fifo = open_port(?CONFIG_PIPE, [eof]),
    {noreply, State#state{fifo = Fifo}};
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
handle_info({Port, {data, Config}},
	    #state{fifo = Port} = State) ->
    {noreply, parse(Config, State)};
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
parse(<<Cmd:8, Len:16, Payload:Len/bytes>>, State) ->
    parse_cmd(Cmd, Payload, State);
parse(Line, State) ->
    Interfaces = string:tokens(Line, " \n"), 
    isis_logger:debug("Recevied config via pipe: ~p", [Interfaces]),
    lists:map(
      fun(L) ->
	      case string:tokens(L, ":") of
		  [Interface, Encap, Mode, Metric] ->
		      isis_logger:debug("Processing: ~p ~p ~p ~p", [Interface, Encap, Mode, Metric]),
		      InterfaceModule = 
			  case Encap of
			      "0" ->
				  isis_interface_l2;
			      "1" ->
				  isis_interface_l3
			  end,
		      InterfaceMode =
			  case Mode of
			      "0" ->
				  broadcast;
			      "1" ->
				  point_to_multipoint
			  end,
                      case isis_system:get_interface(Interface) of
                          unknown ->
                              isis_system:add_interface(Interface, InterfaceModule, InterfaceMode);
                          I ->
                              case (I#isis_interface.interface_module =:= InterfaceModule)
                                  and (I#isis_interface.mode =:= InterfaceMode) of
                                  true ->
                                      noop;
                                  _ ->
                                      isis_system:del_interface(Interface),
                                      isis_system:add_interface(Interface, InterfaceModule, InterfaceMode)
                              end
		      end,
		      %% Now the metric...
		      {MetricInt, []} = string:to_integer(Metric),
		      isis_system:enable_level(Interface, level_1),
		      isis_system:set_interface(Interface, level_1, [{metric, MetricInt}]);
		  Bogus ->
		      isis_logger:error("Ignoring configuration line: ~p", [Bogus])
	      end
      end, Interfaces),
    State.

%%%===================================================================
%%% Parse the new binary-style commands
%%%===================================================================
parse_cmd(1, Payload, State) ->
    isis_logger:debug("Received Interface command with payload: ~p", [Payload]),
    Interfaces = string:tokens(Payload, ","),
    lists:map(
      fun(Interface) ->
              case isis_system:get_interface(Interface) of
                  unknown ->
                      isis_system:add_interface(Interface, isis_interface_l3, point_to_multipoint);
                  I ->
                      case (I#isis_interface.interface_module =:= isis_interace_l3)
                          and (I#isis_interface.mode =:= point_to_multipoint) of
                          true ->
                              noop;
                          _ ->
                              isis_system:del_interface(Interface),
                              isis_system:add_interface(Interface, isis_interface_l3, point_to_multipoint)
                      end
              end
      end, Interfaces),
    State;
parse_cmd(2, Payload, State) ->
    %% wlan0,02:c0:ff:ee:00:0f:00,fe80::c0ff:eeff:fe00:0f00,412
    isis_logger:debug("Received metric information ~p", [Payload]),
    Details = string:tokens(Payload, ","),
    Interface = hd(Details),
    Neighbors = lists:sublist(Details, 2, length(Details)-2),
    [MetricAscii] = lists:sublist(Details, length(Details), 1),
    {Metric, []} = string:to_intger(MetricAscii),
    case isis_system:get_interface(Interface) of
        unknown ->
            noop;
        I ->
            case I#isis_interface.mode of
                point_to_multipoint ->
                    lists:map(
                      fun(N) ->
                              isis_interface:update_metric(I#isis_interface.pid, N, Metric)
                      end, Neighbors);
                _ ->
                    noop
            end
    end,
    State;
parse_cmd(Unknown, Payload, State) ->
    isis_logger:error("Unknown config pipe command: ~p (payload ~p)",
		      [Unknown, Payload]),
    State.
