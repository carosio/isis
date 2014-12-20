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
%%% Created : 08 Dec 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_netconf).

-behaviour(gen_server).

-include_lib("xmerl/include/xmerl.hrl").

%% API
-export([start_link/0, get_state/0]).

-compile(export_all).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(ISIS_NETCONF_NAMESPACES,
	[
	 {"rt", "urn:ietf:params:xml:ns:yang:ietf-routing"},
	 {"v4ur", "urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing"},
	 {"v6ur", "urn:ietf:params:xml:ns:yang:ietf-ipv6-unicast-routing"},
	 {"isis", "urn:ietf:params:xml:ns:yang:ietf-isis"}
	]
       ).

-define(ISIS_XML_BASE,
	"/routing/routing-instance/routing-protocols/routing-protocol/name[. = 'AutoISIS']/../*").

-define(ISIS_Configurators,
	[
	 {"//isis:system-id", fun apply_system_id/3},
	 {"//isis:area-address", fun apply_area_address/3},
	 {"//isis:priority/isis:value", fun apply_interface_priority/3}
	]
       ).

-record(state, {
	  socket,
	  message_buffer = <<>>,
	  last_message
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
get_state() ->
    gen_server:call(?MODULE, {get_state}).

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
    {ok, Socket} = gen_tcp:connect({0,0,0,0,0,0,0,1}, 8301, []),
    {ok, #state{socket = Socket}}.

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
handle_call({get_state}, _From, State) ->
    {reply, State, State};
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
handle_info({tcp, _Port, Bytes}, State) ->
    {noreply, handle_data(Bytes, State)};
handle_info({tcp_closed, _Port}, State) ->
    lager:warning("Netconf: connection to server was closed"),
    {noreply, handle_close(State)};
handle_info(Info, State) ->
    lager:debug("Received unknown info: ~p", [Info]),
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
send_message(Code, Data, State) when is_list(Data) ->
    send_message(Code, list_to_binary(Data), State);
send_message(Code, Data, #state{socket = Socket} = State) ->
    DataLen = byte_size(Data),
    ok = gen_tcp:send(Socket, <<Code:32, DataLen:32, Data/binary>>),
    State.

handle_data(Bytes, #state{message_buffer = MB} = State) ->
    BytesBin = list_to_binary(Bytes),
    NewMB = <<MB/binary, BytesBin/binary>>,
    parse_message(NewMB, State).

parse_message(<<Code:32, Len:32, Data:Len/binary, R/binary>>, State) ->
    NewState = process_message(Code, Data, State),
    parse_message(R, NewState);
parse_message(MB, State) ->
    State#state{message_buffer = MB}.

process_message(0, XML, State) -> % Config request
    lager:info("Netconf: Received a configuration request"),
    %% Parse XML
    {ParsedXML, []} = xmerl_scan:string(binary_to_list(XML),
					[{namespace_conformant, true}]),
    NewState = process_config(ParsedXML, State),
    %% Done
    send_message(1, <<>>, NewState#state{last_message = ParsedXML});
process_message(3, _Data, State) -> % State request
    lager:info("Netconf: Received a state request"),
    {ok, Reply} = process_state(State),
    send_message(4, Reply, State);
process_message(Code, _Data, State) ->
    lager:warning("Netconf: Received unknown message with code: ~p", [Code]),
    State.

handle_close(State) ->
    State#state{socket = undefined}.

process_config(ParsedXML, State) ->
    lists:map(fun(Line) ->
		      configurator(Line, ParsedXML, State)
	      end, ?ISIS_Configurators),
    State.

get_namespace_uri(Prefix) ->
    {Prefix, Uri} = lists:keyfind(Prefix, 1, ?ISIS_NETCONF_NAMESPACES),
    Uri.

process_state(State) ->
    MainNamespace = #xmlAttribute{name = 'xmlns', value = get_namespace_uri("rt")},
    Namespaces = lists:map(fun({Prefix, Url}) ->
			       #xmlAttribute{
				   name = list_to_atom("xmlns:" ++ Prefix),
				   value = Url
			       }
			   end, ?ISIS_NETCONF_NAMESPACES),
    Root = #xmlElement{
	name = 'routing-state',
	attributes = [MainNamespace | Namespaces],
	content = [
	    #xmlElement{name = 'routing-instance', content = [
		#xmlElement{name = 'name', content = [ #xmlText{value = "default"} ]},
		#xmlElement{name = 'id', content = [ #xmlText{value = "1"} ]},
		#xmlElement{name = 'type', content = [ #xmlText{value = "rt:default-routing-instance"} ]},
		#xmlElement{name = 'default-ribs', content = [
		    #xmlElement{name = 'default-rib', content = [
		        #xmlElement{name = 'address-family', content = [ #xmlText{value = "ipv6"} ]},
		        #xmlElement{name = 'rib-name', content = [ #xmlText{value = "main-ipv6"} ]}
		    ]},
		    #xmlElement{name = 'default-rib', content = [
		        #xmlElement{name = 'address-family', content = [ #xmlText{value = "ipv4"} ]},
		        #xmlElement{name = 'rib-name', content = [ #xmlText{value = "main-ipv4"} ]}
		    ]}
		]},
		#xmlElement{name = 'interfaces', content = get_interface_state(State)},
		#xmlElement{name = 'routing-protocols', content = [
		    #xmlElement{name = 'routing-protocol', content = [
			#xmlElement{name = 'type', content = [ #xmlText{value = "isis:isis"} ]},
			#xmlElement{name = 'name', content = [ #xmlText{value = "AutoISIS"} ]},
			#xmlElement{name = 'isis', content = get_isis_state(State), attributes = [
			    #xmlAttribute{name = 'xmlns', value = get_namespace_uri("isis")}
			]}
		    ]}
		]}
	    ]}
	]
    },
    {ok, lists:flatten(xmerl:export([Root], xmerl_xml))}.

%% This function should return [#xmlElement] with the existing interfaces
%% in the current routing-instance.
%% That might be something we don't want to do in IS-IS, let's see whether we can
get_interface_state(_State) ->
    [].

%% This function should return [#xmlElement] for the subtree
%% routing-state/routing-instance/routing-protocols/isis subtree
get_isis_state(State) ->
    [
	#xmlElement{name = 'system-counters', content = [
	]},
	#xmlElement{name = 'interface-counters', content = [
	]},
	#xmlElement{name = 'packet-counters', content = [
	]},
	#xmlElement{name = 'interfaces', content = [
	]},
	#xmlElement{name = 'adjacencies', content = [
	]},
	#xmlElement{name = 'spf-log', content = [
	]},
	#xmlElement{name = 'lsp-log', content = [
	]},
	#xmlElement{name = 'database', content = [
	]},
	#xmlElement{name = 'hostnames', content = get_isis_hostnames_state()}
    ].

%% This function should return [#xmlElement] for the subtree
%% routing-state/routing-instance/routing-protocols/isis/hostnames
get_isis_hostnames_state() ->
    HostNameGen = fun({SystemId, Name}) ->
	<<A:16, B:16, C:16>> = SystemId,
	FormattedId = lists:flatten(io_lib:format("~4.16.0B.~4.16.0B.~4.16.0B.00", [A,B,C])),
	#xmlElement{name = 'hostname', content = [
	    #xmlElement{name = 'system-id', content = [ #xmlText{value = FormattedId} ]},
	    #xmlElement{name = 'hostname', content = [ #xmlText{value = Name} ]}
	]}
    end,
    lists:map(HostNameGen, isis_system:all_names()).

configurator({Pattern, Applicator}, XML, State) ->
    Nodes = xpath(Pattern, XML),
    Apply = fun(N) -> Applicator(N, XML, State) end,
    lists:map(Apply, Nodes).

%%%===================================================================
%%% Configuration helpers
%%%===================================================================

xpath(Pattern, XML) ->
    xpath(Pattern, XML, []).
xpath(Pattern, XML, Options) ->
    xpath(Pattern, XML, [], XML, Options).
xpath(Pattern, Node, Parents, Doc, Options) ->
    DefaultOptions =
      [
       {namespace, ?ISIS_NETCONF_NAMESPACES}
      ],
    xmerl_xpath:string(Pattern, Node, Parents,
		       Doc, DefaultOptions ++ Options).

xml_get_value(text, Node) ->
    Content = Node#xmlElement.content,
    [T] =
	lists:filter(fun(#xmlText{}) ->
			     true;
			(_) ->
			 false
		     end, Content),
    T#xmlText.value;
xml_get_value(_, _) ->
    error.

extract_interface(Node, XML) ->
    Interface =
	xml_get_value(
	  text,
	  hd(xpath("../../../isis:interface/isis:name", Node,
		   Node#xmlElement.parents, XML, []))),
    string:strip(Interface, both, $").

extract_level(Node, XML) ->
    Level =
	xml_get_value(
	  text,
	  hd(xpath("../isis:level", Node,
		   Node#xmlElement.parents, XML, []))),
    case Level of
	"level-1" ->
	    level_1;
	"level-2" ->
	    level_2;
	"level-all" ->
	    level_1_2
    end.
    
%%%===================================================================
%%% Configuration functions
%%%===================================================================
apply_system_id(Node, _XML, _State) ->
    Value = xml_get_value(text, Node),
    lager:info("Netconf: Found system-id ~p", [Value]),
    ID = string:tokens(Value, "."),
    IDBint = 
	lists:map(
	  fun(X) when length(X) =:= 4 ->
		  <<(list_to_integer(X, 16)):16>>;
	     ("00") ->
		  <<>>
	  end, ID),
    SystemID = lists:foldl(fun(X, Acc) -> <<Acc/binary, X/binary>> end, <<>>, IDBint),
    isis_system:set_system_id(SystemID).

apply_area_address(Node, _XML, _State) ->
    Value = xml_get_value(text, Node),
    lager:info("Netconf: Found area address ~p", [Value]),
    AreaBits = string:tokens(Value, "."),
    AreaBin = 
	lists:map(
	  fun(X) when length(X) =:= 4 ->
		  <<(list_to_integer(X, 16)):16>>;
	     (X) when length(X) =:= 2 ->
		  <<(list_to_integer(X, 16)):8>>
	  end, AreaBits),
    Area = lists:foldl(fun(X, Acc) -> <<Acc/binary, X/binary>> end, <<>>, AreaBin),
    isis_system:add_area(Area).

apply_interface_priority(Node, XML, _State) ->
    Value = list_to_integer(xml_get_value(text, Node), 10),
    lager:info("Netconf: Found interface priority ~p", [Value]),
    Interface = extract_interface(Node, XML),
    lager:info("Netconf: Interface is ~p", [Interface]),
    Level = extract_level(Node, XML),
    isis_system:add_interface(Interface),
    isis_system:enable_level(Interface, Level),
    isis_system:set_interface(Interface, Level,
			      [{priority, Value}]).
