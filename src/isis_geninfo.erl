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
%%% Created : 20 Nov 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_geninfo).
-author("Rick Payne <rickp@rossfell.co.uk>").

-include("isis_system.hrl").
-include("isis_protocol.hrl").
-include("isis_geninfo.hrl").

-behaviour(gen_server).

%% API
-export([start_link/0, register_client/1,
	 announce/1, withdraw/1,
	 clients/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
	  tlvs,        %% LSP-ID -> Geninfo TLVs within the LSP
	  clients,     %% Dict that maps pid -> #isis_geninfo_client{}
	  refresh_timer = undefined
	 }).

%%%===================================================================
%%% API
%%%===================================================================
register_client(#isis_geninfo_client{} = GI) ->
    gen_server:call(?MODULE, {register, GI, self()});
register_client(_) ->
    invalid.

announce(TLVs) ->
    gen_server:cast(?MODULE, {announce, TLVs, self()}).

withdraw(TLVs) ->
    gen_server:cast(?MODULE, {withdraw, TLVs, self()}).

clients() ->
    gen_server:call(?MODULE, {clients}).

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
    %% Subscribe to LSP updates
    Subscribe =
	fun(L) ->
		isis_lspdb:subscribe(L, self(), struct),
		isis_lspdb:initial_state(L, self(), struct)
	  end,
    Subscribe(level_1),
    Subscribe(level_2),
    %% Lets go!
    {ok, #state{tlvs = dict:new(), clients = dict:new()}}.

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
handle_call({clients}, From, #state{clients = Clients} = State) ->
    io:format("From: ~p~n", [From]),
    {reply, Clients, State};
handle_call({register, GI, Pid}, _From, State) ->
    {Reply, NewState} = register(GI, Pid, State),
    {reply, Reply, NewState};
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
handle_cast({announce, TLVs, From}, State) ->
    {noreply, announce_tlvs(TLVs, From, State)};
handle_cast(Msg, State) ->
    lager:debug("Failed to handle cast ~p", [Msg]),
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
handle_info({timeout, _Ref, refresh}, State) ->
    NextState = install_frags(State),
    {noreply, NextState#state{refresh_timer = undefined}};
handle_info({lsp_update, Message}, State) ->
    NewState = process_lsp_update(Message, State),
    {noreply, NewState};
handle_info({'DOWN', _, process, Pid, _}, State) ->
    {noreply, unregister(Pid, State)};
handle_info(Info, State) ->
    lager:debug("Failed to handle Info ~p", [Info]),
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
register(#isis_geninfo_client{app = AppID, ip = AppIP} = GI, Pid,
	 #state{clients = C} = State) ->
    %% Anything else in the dict for this {ID, Address} ?
    case length(dict:to_list(
		  dict:filter(fun(_, {A, B}) when A=:=AppID, B=:=AppIP ->
				      true;
				 (_, _) ->
				      false
			      end, C))) of
	0 ->
	    erlang:monitor(process, Pid),
	    {ok,
	     State#state{clients =
			     dict:store(Pid, GI, C)}};
	_ ->
	    {already_in_use, State}
    end.
				     
unregister(Pid, #state{clients = C} = State) ->
    NewC =
	dict:filter(fun(K, GI) when K =:= Pid ->
			    remove_all_tlvs(GI),
			    false;
		       (_, _) ->
			    true
		    end, C),
    State#state{clients = NewC}.

start_timer(#state{refresh_timer = RT} = State) when RT =:= undefined ->
    T = erlang:start_timer(isis_protocol:jitter(?GENINFO_REFRESH_TIME,
						?GENINFO_JITTER),
			   self(), refresh),
    State#state{refresh_timer = T};
start_timer(State) ->
    %% Timer arleady running...
    State.

process_lsp_update({add, Level, #isis_lsp{tlv = TLVs, lsp_id = LSPId} = LSP},
		    State) ->
    %% Get list of geninfo TLVs in the LSP and previous
    CurrentGIT = extract_geninfo(TLVs),
    PreviousGIT =
	case dict:find({Level, LSPId}, State#state.tlvs) of
	    {ok, T} -> T;
	    _ -> []
	end,
    %% Convert list into a set of {AppID, AppIP, Gunk} items so we can intersect
    CurrentSet = sets:from_list(geninfo_list(CurrentGIT)),
    PreviousSet = sets:from_list(geninfo_list(PreviousGIT)),
    %% Create two lists - one of newly added GenInfos and one of removed GenInfos
    Added = sets:to_list(sets:subtract(CurrentSet, PreviousSet)),
    Deleted = sets:to_list(sets:subtract(PreviousSet, CurrentSet)),
    %% Now update any subscriber
    update_subscribers(Added, Deleted, LSPId, State),
    %% Store the current set ready for next time
    NewTLVs = dict:store({Level, LSP#isis_lsp.lsp_id}, CurrentGIT, State#state.tlvs),
    State#state{tlvs = NewTLVs};
process_lsp_update({delete, Level, LSPId}, State) ->
    NewTLVs = dict:erase({Level, LSPId}, State#state.tlvs),
    State#state{tlvs = NewTLVs}.

%% Turn our set of per-client frags into TLVs and then install
install_frags(#state{clients = C} = State) ->
    NewClients = 
	dict:map(fun(_Pid, GI) ->
			 install_frags_client(GI)
		 end, C),
    State#state{clients = NewClients}.

install_frags_client(#isis_geninfo_client{frags = Frags} = GI) ->
    NewFrags = 
	lists:map(
	  fun(#isis_geninfo_frag{updated = false} = F) -> F;
	     (#isis_geninfo_frag{} = F) -> announce_frag(F, GI)
	  end, Frags),
    GI#isis_geninfo_client{frags = NewFrags}.

announce_frag(#isis_geninfo_frag{tlvs = TLVs,
				 remaining_size = RS,
				 previous_encode = PreviousEncode},
	      #isis_geninfo_client{app = App, ip = IP, level = Level,
				   encode_func = EncodeFunc}) ->
    case PreviousEncode of
	<<>> ->
	    ok;
	PE -> 
	    OldTLV = #isis_tlv_geninfo{
			application_id = App,
			application_ip_address = IP,
			application_gunk = PE},
	    isis_system:delete_tlv(OldTLV, 0, Level, undefined)
    end,
    Gunk = 
	lists:foldl(
	  fun(T, Acc) -> <<Acc/binary, (EncodeFunc(T))/binary>> end,
	  <<>>, TLVs),
    NewTLV = #isis_tlv_geninfo{
		application_id = App,
		application_ip_address = IP,
		application_gunk = Gunk},
    isis_system:update_tlv(NewTLV, 0, Level, undefined),
    #isis_geninfo_frag{
       tlvs = TLVs,
       remaining_size = RS,
       previous_encode = Gunk,
       updated = false}.

remove_all_tlvs(#isis_geninfo_client{
		   app = App, ip = IP, level = Level,
		   frags = Frags}) ->
    lists:map(
      fun(#isis_geninfo_frag{
	    previous_encode = PE}) when PE =/= <<>> ->
	      isis_system:delete_tlv(#isis_tlv_geninfo{
					application_id = App,
					application_ip_address = IP,
					application_gunk = PE},
				     0, Level, undefined);
	 (_) -> ok
      end, Frags).

%% Extract just the geninfo TLVs
extract_geninfo(TLVs) ->
    lists:filter(fun(#isis_tlv_geninfo{}) ->
			 true;
		    (_) ->
			 false
		 end, TLVs).

geninfo_list(TLVs) ->
    lists:map(fun(#isis_tlv_geninfo{
		     application_id = AID,
		     application_ip_address = AIP,
		     application_gunk = AG}) ->
		      {AID, AIP, AG}
	      end, TLVs).

update_subscribers(Added, Deleted, LSPId, State) ->
    Conv = fun({AID, AIP, Gunk}, D) ->
		   dict:store({AID, AIP}, Gunk, D)
	   end,
    AddedDict = lists:foldl(Conv, dict:new(), Added),
    DeletedDict = lists:foldl(Conv, dict:new(), Deleted),
    Clients = dict:to_list(State#state.clients),
    lists:map(
      fun({Pid, #isis_geninfo_client{app = A, ip = I} = GI}) ->
	      lager:error("Updating client: ~p ~p", [Added, Deleted]),
	      case dict:find({A, I}, DeletedDict) of
		  {ok, DelG} ->
		      %% Update client
		      Ts = parse_tlvs(DelG, GI),
		      Pid ! {delete, LSPId, Ts};
		  _ -> ok
	      end,
	      case dict:find({A, I}, AddedDict) of
		  {ok, AddG} ->
		      %% Send to client
		      DecodedT = parse_tlvs(AddG, GI),
		      Pid ! {add, LSPId, DecodedT};
		  _ -> ok
	      end
      end, Clients).

parse_tlvs(G, GI) ->
    parse_tlvs(G, GI, []).

parse_tlvs(<<T:8, S:8, V:S/binary, R/binary>>,
	   #isis_geninfo_client{decode_func = DecodeFunc} = GI, Acc) ->
    parse_tlvs(R, GI, [DecodeFunc(T, V) | Acc]);
parse_tlvs(<<>>, _, Acc) ->
    lists:reverse(Acc).

announce_tlvs(TLVs, From, #state{clients = C} = State) ->
    case dict:find(From, C) of
	{ok, GI} ->
	    NewClient = update_tlvs(TLVs, GI),
	    start_timer(State#state{clients = dict:store(From, NewClient, C)});
	error ->
	    State
    end.

%% Given a set of TLVs from a client, then merge them as efficiently
%% as possible into a TLV Frag
update_tlvs(TLVs, GI) ->
    %% Convert TLV list into {Size, MergeType, TLV} for ease
    SizedTLVs =
	lists:map(
	  fun(T) ->
		  MergeType = (GI#isis_geninfo_client.mergetype_func)(T),
		  ET = (GI#isis_geninfo_client.encode_func)(T),
		  {T, MergeType, byte_size(ET)}
	  end, TLVs),
    Frags = GI#isis_geninfo_client.frags,
    NewFrags = 
	lists:foldl(fun(ST, Fs) -> update_frags(ST, Fs, GI) end,
		    Frags, SizedTLVs),
    GI#isis_geninfo_client{frags = NewFrags}.

%% Take 1 TLV (which we've already expanded to include size and
%% mergetype and see if we can install it into one of the existing
%% frags (based on mergetype).
%% Must return a new Frags list
update_frags({TLV, MergeType, Size}, Frags, GI) ->
    %% Walk the set of frags and try and update, which will be based
    %% on MergeType.
    {NewFrags, Updated} = 
	lists:mapfoldl(fun(Frag, false) ->
			       %% Not updated yet, so give it a go in this frag
			       update_individual_frag(MergeType, TLV, Size, Frag, GI);
			  (Frag, true) ->
			       %% We've already inserted it, so no need to do more...
			       Frag
		       end, false, Frags),
    case Updated of
	true ->
	    %% No more work to do...
	    NewFrags;
	false ->
	    %% Need to create a new frag
	    [#isis_geninfo_frag{
	       remaining_size = tlv_base_size(GI) - Size,
	       tlvs = [TLV]
	      } | NewFrags]
    end.

%% Given an expanded TLV and a Frag, so if we can
%% replace/add/merge_array.  Return should be of the format {NewFrag,
%% updated} where updated is true if we have managed to find a home
%% for the given TLV.
update_individual_frag(replace, T, TSize,
		      #isis_geninfo_frag{remaining_size = RemainingSize,
					 tlvs = FragTLVs},
		       GI) ->
    FoundTLVs = 
	lists:filter(fun(TT) -> element(1, T) =:= element(1, TT) end, FragTLVs),
    OldSize =
	lists:foldl(fun(FT, Acc) -> Acc+byte_size((GI#isis_geninfo_client.encode_func)(FT)) end,
		    0, FoundTLVs),
    CleanedFrags = lists:filter(fun(CF) -> element(1, CF) =/= element(1, T) end, FragTLVs),
    case RemainingSize >= (OldSize - TSize) of
	true ->
	    {#isis_geninfo_frag{
		updated = true,
		remaining_size = RemainingSize + (OldSize - TSize),
		tlvs = [T | CleanedFrags]},
	     true};
	false ->
	    {#isis_geninfo_frag{
		updated = OldSize =/= 0,
		remaining_size = RemainingSize - OldSize,
		tlvs = CleanedFrags},
	     false}
    end;
update_individual_frag(_, _, _, _, _) ->
    invalid.
				      
tlv_base_size(#isis_geninfo_client{
	     ip = defined}) ->
    %% We use 1 + 2 bytes for header
    255 - 3;
tlv_base_size(#isis_geninfo_client{
	    ip = #isis_address{afi = ipv4}}) ->
    255 - 3 - 4;
tlv_base_size(#isis_geninfo_client{
	    ip = #isis_address{afi = ipv6}}) ->
    255 - 3 - 16.
