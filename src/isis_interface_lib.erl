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
%%% Created : 05 Jul 2015 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_interface_lib).

-include("isis_system.hrl").
-include("isis_protocol.hrl").
-include("isis_interface_lib.hrl").

%%% Library of useful functions shared between isis_interface_level
%%% and isis_interface_p2mp

-export(
   [verify_authentication/2,
    announce_lsps/2,
    handle_psnp/2,
    handle_lsp/2,
    handle_csnp/2,
    send_psnp/1,
    send_csnp/1]).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Take 2 lists of isis_lsp_tlv_entry_details - the first from our
%% database, the second from the CSNP packet. We iterate the lists:
%%   If the LSP is on the first, but not the second, we need to announce
%%   If the LSP is on the second, but not eh first - we must request it
%%   If the LSP is on both, check the sequence number...
%% The reason to do it this way is efficiency...
%%
%% @end
%%--------------------------------------------------------------------
-spec compare_lsp_entries([isis_tlv_lsp_entry_detail()],
			  [isis_tlv_lsp_entry_detail()], {[binary()], [binary()]}) ->
				 {[binary()], [binary()]}.
compare_lsp_entries([#isis_tlv_lsp_entry_detail{lsp_id = L, sequence = LN} | LT],
		    [#isis_tlv_lsp_entry_detail{lsp_id = H, sequence = HN} | HT],
		    {Request, Announce})
  when L == H, LN < HN ->
    compare_lsp_entries(LT, HT, {[L | Request], Announce});
compare_lsp_entries([#isis_tlv_lsp_entry_detail{lsp_id = L, sequence = LN} | LT],
		    [#isis_tlv_lsp_entry_detail{lsp_id = H, sequence = HN} | HT],
		    {Request, Announce})
  when L == H, LN > HN ->
    compare_lsp_entries(LT, HT, {Request, [H | Announce]});
compare_lsp_entries([#isis_tlv_lsp_entry_detail{lsp_id = L, sequence = LN} | LT],
		    [#isis_tlv_lsp_entry_detail{lsp_id = H, sequence = HN} | HT],
		    {Request, Announce})
  when L == H, LN == HN ->
    compare_lsp_entries(LT, HT, {Request, Announce});
compare_lsp_entries([#isis_tlv_lsp_entry_detail{lsp_id = L} | LT],
		    [#isis_tlv_lsp_entry_detail{lsp_id = H} | _HT] = L2,
		    {Request, Announce})
  when L < H ->
    compare_lsp_entries(LT, L2, {Request, [L | Announce]});
compare_lsp_entries([#isis_tlv_lsp_entry_detail{lsp_id = L} | _LT] = L1,
		    [#isis_tlv_lsp_entry_detail{lsp_id = H} | HT],
		    {Request, Announce})
  when L > H ->
    compare_lsp_entries(L1, HT, {[H | Request], Announce});
compare_lsp_entries([],
		    [#isis_tlv_lsp_entry_detail{lsp_id = H} | HT],
		    {Request, Announce}) ->
    %% We're missing an LSP, add to the request list
    compare_lsp_entries([], HT, {[H | Request], Announce});
compare_lsp_entries([#isis_tlv_lsp_entry_detail{lsp_id = L} | LT],
		    [],
		    {Request, Announce}) ->
    %% We have the LSP but the neighbor doesn't, so add to the announce list
    compare_lsp_entries(LT, [], {Request, [L | Announce]});
compare_lsp_entries([], [], {Request, Announce}) ->
    {lists:reverse(Request), lists:reverse(Announce)}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Given a list of LSPs, announce them...
%%
%% @end
%%--------------------------------------------------------------------
-spec announce_lsps(list(), tuple()) -> ok.
announce_lsps(IDs, State) ->
    LSPs = isis_lspdb:lookup_lsps(lists:sort(IDs),
				  State#isis_pdu_state.database),
    send_lsps(LSPs, State),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Given a list of LSPs, send them out....
%%
%% @end
%%--------------------------------------------------------------------
-spec send_lsps([isis_lsp()], tuple()) -> ok.
send_lsps(LSPs, #isis_pdu_state{parent = Parent,
				parent_pid = Parent_pid,
				level = Level} = State) ->
    %% AuthTLV = authentication_tlv(State),
    lists:map(fun(#isis_lsp{} = L) ->
		      %% NewTLVs = AuthTLV ++ TLVs,
		      try isis_protocol:encode(L, none) of
			  {ok, Bin, Len} ->
			      isis_logger:debug("Sending LSP: ~p", [L]),
			      Parent:send_pdu(Parent_pid, lsp, Bin, Len, Level);
			  _ -> isis_logger:error("Failed to encode LSP ~p~n",
					   [L#isis_lsp.lsp_id])
		      catch
			  error:Fail ->
			      isis_logger:error("Failed to encode: ~p (~p)", [L, Fail])
		      end
	      end, LSPs),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Add the list of LSPs to the SSN gb_trees, ready to be sent. Start
%% the timer running if one isn't already running.
%%
%% @end
%%--------------------------------------------------------------------
-spec update_ssn([binary()], tuple()) -> tuple().
update_ssn(LSP_Ids, #isis_pdu_state{ssn = SSN,
				    parent_pid = Parent_pid} = State) ->
    Timer = 
	case State#isis_pdu_state.ssn_timer of
	    undef -> erlang:start_timer(isis_protocol:jitter(?ISIS_PSNP_TIMER, ?ISIS_PSNP_JITTER),
					Parent_pid, ssn);
	    _ -> State#isis_pdu_state.ssn_timer
	end,
    L = SSN ++ LSP_Ids,
    State#isis_pdu_state{ssn = L, ssn_timer = Timer}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Take the list of LSP IDs in the SSN field, and generate the PSNP
%% messages.
%%
%% @end
%%--------------------------------------------------------------------
-spec send_psnp(tuple()) -> tuple().
send_psnp(#isis_pdu_state{database = DB,
			  ssn = SSN,
			  parent = Parent,
			  parent_pid = Parent_pid,
			  level = Level} = State) ->
    SID = State#isis_pdu_state.system_id,
    Source = <<SID:6/binary, 0:8>>,
    PDU_Type =
	case State#isis_pdu_state.level of
	    level_1 -> level1_psnp;
	    level_2 -> level2_psnp
	end,
    AuthTLV = isis_protocol:authentication_tlv(State#isis_pdu_state.level_authentication),
    TLVs = 
	lists:map(fun(LSP) ->
			  %% Be better if we could do one lookup for
			  %% all, but then we don't know which ones we
			  %% don't have.
			  case isis_lspdb:lookup_lsps([LSP], DB) of
			      [L] -> #isis_tlv_lsp_entry_detail{lsp_id = LSP,
								lifetime = L#isis_lsp.remaining_lifetime,
								sequence = L#isis_lsp.sequence_number,
								checksum = L#isis_lsp.checksum};
			      _ -> %% We have no matching LSP, so send a blank PSNP
				  #isis_tlv_lsp_entry_detail{lsp_id = LSP}
			  end
		  end, SSN),

    DetailPackageFun = fun(F) -> [#isis_tlv_lsp_entry{lsps = F}] end,			 
    TLVPackageFun = fun(F) -> [#isis_psnp{pdu_type = PDU_Type,
					  source_id = Source,
					  tlv = AuthTLV ++ F}]
		    end,

    %% Now we have the detail entries we need to bundle up as many
    %% entries as can be fitted into the 255 byte TLV limit and then
    %% as many TLVs as can be fitted into a messgae (based on MTU).
    List_of_TLVs = isis_protocol:package_tlvs(TLVs, DetailPackageFun,
					      ?LSP_ENTRY_DETAIL_PER_TLV),
    List_of_PDUs = isis_protocol:package_tlvs(List_of_TLVs, TLVPackageFun,
					      ?LSP_ENTRY_PER_PDU),
    lists:map(fun(F) ->
		      case isis_protocol:encode(F, State#isis_pdu_state.level_authentication) of
			  {ok, Bin, Len} ->
			      isis_logger:debug("Sending PSNP: ~p", [F]),
			      Parent:send_pdu(Parent_pid, psnp, Bin, Len, Level);
			  _ -> io:format("Bad encoding for ~p~n", [F])
		      end
	      end,
	      List_of_PDUs),
    State#isis_pdu_state{ssn = []}.
		     
%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% A PSNP is either ack-ing an LSP we've sent, or its requesting
%% specific LSPs. So if the sequence number is set, then we should
%% send the LSP. Otherwise, there's nothing to do.
%%
%% @end
%%--------------------------------------------------------------------
-spec handle_psnp(isis_psnp(), tuple()) -> ok | error.
handle_psnp(_, #isis_pdu_state{database = DB} = State) when DB =:= undef ->
    State;
handle_psnp(#isis_psnp{tlv = TLVs},
	    #isis_pdu_state{database = DB} = State) ->
    %% Extract and create lsp_entry_detail records for the range from
    %% our datbase
    PSNP_LSPs =
	lists:foldl(fun(F, Acc) ->
			    case is_record(F, isis_tlv_lsp_entry) of
				true -> Acc ++ F#isis_tlv_lsp_entry.lsps;
				_ -> Acc
			    end
		    end,
		    [], TLVs),

    ToSend = 
	lists:filtermap(
	  fun(#isis_tlv_lsp_entry_detail{lsp_id = LSP, sequence = Seq}) ->
		  case isis_lspdb:lookup_lsps([LSP], DB) of
		      [L] ->
			  case Seq < L#isis_lsp.sequence_number of
			      true -> {true, L};
			      _ -> false
			  end;
		      _ -> false
		  end
	  end, PSNP_LSPs),
    send_lsps(ToSend, State),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% A PSNP is either ack-ing an LSP we've sent, or its requesting
%% specific LSPs. So if the sequence number is set, then we should
%% send the LSP. Otherwise, there's nothing to do.
%%
%% @end
%%--------------------------------------------------------------------
-spec handle_lsp(isis_lsp(), tuple()) -> tuple().
handle_lsp(#isis_lsp{lsp_id = ID, remaining_lifetime = 0} = LSP,
	   #isis_pdu_state{level = Level} = State) ->
    %% Purging the lsp...
    isis_logger:info("Purging LSP ~p", [ID]),
    isis_lspdb:store_lsp(Level,
			 LSP#isis_lsp{tlv = [],
				      remaining_lifetime = 0,
				      last_update = isis_protocol:current_timestamp()});
handle_lsp(#isis_lsp{lsp_id = ID, sequence_number = TheirSeq} = LSP,
	   #isis_pdu_state{database = DB, system_id = SID, level = Level} = State) ->
    <<RemoteSys:6/binary, _Rest/binary>> = ID,
    NewState = 
	case RemoteSys =:= SID of
	    true ->
		%% Returns our New State
		handle_old_lsp(LSP, State);
	    _ ->
		L = isis_lspdb:lookup_lsps([ID], DB),
		Announce = 
		    case length(L) of
			1 -> [OurLSP] = L,
			     OurSeq = OurLSP#isis_lsp.sequence_number,
			     case (OurSeq < TheirSeq) of
				 true -> isis_lspdb:store_lsp(Level, LSP),
					 isis_logger:warning("Updated LSP (~b vs ~b)~n", [OurSeq, TheirSeq]),
					 true;
				 _ -> case State#isis_pdu_state.are_we_dis of
					  true -> send_lsps([OurLSP], State);
					  _ -> ok
				      end,
				      false
			     end;
			0 -> isis_lspdb:store_lsp(Level, LSP),
			     update_ssn([LSP#isis_lsp.lsp_id], State),
			     isis_logger:warning("New LSP, storing..~n", []),
			     true;
			_ -> false
		    end,
		case Announce of
		    true -> flood_lsp(LSP, State),
			    State;
		    _ -> update_ssn([LSP#isis_lsp.lsp_id], State)
		end
	end,
    NewState.

handle_old_lsp(#isis_lsp{lsp_id = ID, tlv = TLVs,
			 sequence_number = SeqNo} = LSP,
	       #isis_pdu_state{database = DB, level = Level,
				    level_authentication = LA} = State) ->
    case isis_system:check_autoconf_collision(TLVs) of
	false ->
	    case isis_lspdb:lookup_lsps([ID], DB) of
		[#isis_lsp{sequence_number = SN}] ->
		    case SeqNo > SN of
			true ->
			    <<_:6/binary, Node:8, Frag:8>> = ID,
			    isis_system:bump_lsp(Level, Node, Frag, SeqNo);
			_ -> ok
		    end;
		_ ->
		    isis_logger:error("Purging an old LSP that claims to be from us: ~p",
				[ID]),
		    PLSP =
			LSP#isis_lsp{tlv = isis_protocol:authentication_tlv(LA),
				     remaining_lifetime = 0,
				     sequence_number = SeqNo + 1, checksum = 0,
				     last_update = isis_protocol:current_timestamp()},
		    isis_lspdb:store_lsp(Level, PLSP),
		    isis_lspdb:flood_lsp(Level,
					 isis_system:list_circuits(),
					 PLSP, LA),
		    purged
	    end;
	_ -> ok
    end,
    State.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Take the range from the CNSP packet and compare the LSP entries
%% with our database.
%%
%% @end
%%--------------------------------------------------------------------
-spec handle_csnp(isis_csnp(), tuple()) -> tuple().
handle_csnp(_, #isis_pdu_state{database = DB} = State) when DB =:= undef ->
    State;
handle_csnp(#isis_csnp{start_lsp_id = Start,
		       end_lsp_id = End,
		       tlv = TLVs},
	    #isis_pdu_state{database = DB} = State) ->
    %% Extract and create lsp_entry_detail records for the range from
    %% our datbase
    DB_LSPs = 
	lists:map(fun({ID, Seq, Check, Life}) ->
			  #isis_tlv_lsp_entry_detail{lifetime = Life,
						     lsp_id = ID,
						     sequence = Seq,
						     checksum = Check}
		  end,
		  isis_lspdb:range(Start, End, DB)),

    %% Convert the CSNP TLVs into a single list of lsp_entry_details...
    CSNP_LSPs =
	lists:foldl(fun(F, Acc) ->
			    case is_record(F, isis_tlv_lsp_entry) of
				true -> Acc ++ F#isis_tlv_lsp_entry.lsps;
				_ -> Acc
			    end
		    end,
		    [], TLVs),

    %% Compare the 2 lists, to get our announce/request sets
    {Request, Announce} = compare_lsp_entries(DB_LSPs, CSNP_LSPs, {[], []}),
    announce_lsps(Announce, State),
    %% isis_logger:debug("CSNP on ~s: ~p", [State#state.interface_name, isis_logger:pr(CSNP, isis_protocol)]),
    %% isis_logger:debug("DB: ~p", [isis_logger:pr(DB_LSPs, isis_protocol)]),
    isis_logger:debug("Announce: ~p, Request: ~p", [Announce, Request]),
    NewState = update_ssn(Request, State),
    NewState.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Authenticating for 'text' is simple - that only works on the iih.
%% For MD5 we need to check all PDU types, resetting the sig to zero
%% and for LSP we reset the remaining lifetime & checksum to zero too
%%
%% @end
%%--------------------------------------------------------------------
verify_authentication(#isis_iih{tlv = TLVs} = PDU, State) ->
    verify_authentication(TLVs, PDU, State#isis_pdu_state.authentication);
verify_authentication(#isis_p2p_iih{tlv = TLVs} = PDU, State) ->
    verify_authentication(TLVs, PDU, State#isis_pdu_state.authentication);
verify_authentication(#isis_lsp{tlv = TLVs} = PDU, State) ->
    verify_authentication(TLVs, PDU, State#isis_pdu_state.level_authentication);
verify_authentication(#isis_csnp{tlv = TLVs} = PDU, State) ->
    verify_authentication(TLVs, PDU, State#isis_pdu_state.level_authentication);
verify_authentication(#isis_psnp{tlv = TLVs} = PDU, State) ->
    verify_authentication(TLVs, PDU, State#isis_pdu_state.level_authentication).

verify_authentication(_, _, none) ->
    valid;
verify_authentication(TLVs, #isis_iih{}, {text, Key}) ->
   case isis_protocol:filter_tlvs(isis_tlv_authentication, TLVs) of
       [#isis_tlv_authentication{
	  type = text, signature = Key}] -> valid;
       [] -> missing_auth;
       _ -> invalid
   end;
verify_authentication(TLVs, #isis_iih{} = PDU, {md5, Key}) ->
    {ResetTLVs, Sig} = get_reset_md5_tlv(TLVs),
    MD5IIH = PDU#isis_iih{tlv = ResetTLVs},
    verify_authentication_md5(MD5IIH, Key, Sig);
verify_authentication(TLVs, #isis_p2p_iih{}, {text, Key}) ->
   case isis_protocol:filter_tlvs(isis_tlv_authentication, TLVs) of
       [#isis_tlv_authentication{
	  type = text, signature = Key}] -> valid;
       [] -> missing_auth;
       _ -> invalid
   end;
verify_authentication(TLVs, #isis_p2p_iih{} = PDU, {md5, Key}) ->
    {ResetTLVs, Sig} = get_reset_md5_tlv(TLVs),
    MD5IIH = PDU#isis_p2p_iih{tlv = ResetTLVs},
    verify_authentication_md5(MD5IIH, Key, Sig);
verify_authentication(_, #isis_lsp{}, {text, _}) ->
    valid;
verify_authentication(_TLVs, #isis_csnp{}, {text, _}) ->
    valid;
verify_authentication(TLVs, #isis_csnp{} = PDU, {md5, Key}) ->
    {ResetTLVs, Sig} = get_reset_md5_tlv(TLVs),
    MD5CSNP = PDU#isis_csnp{tlv = ResetTLVs},
    verify_authentication_md5(MD5CSNP, Key, Sig);
verify_authentication(_TLVs, #isis_psnp{}, {text, _}) ->
    valid;
verify_authentication(TLVs, #isis_psnp{} = PDU, {md5, Key}) ->
    {ResetTLVs, Sig} = get_reset_md5_tlv(TLVs),
    MD5PSNP = PDU#isis_psnp{tlv = ResetTLVs},
    verify_authentication_md5(MD5PSNP, Key, Sig);
verify_authentication(_, _PDU, {md5, _}) ->
    valid;
verify_authentication(_, _, _) ->
    error.

%% Take a set of TLVs, extract the MD5 signature, and
%% reset it to zeros, ready for computing the hash...
get_reset_md5_tlv(TLVs) ->
    lists:mapfoldl(
      fun(#isis_tlv_authentication{type = md5,
				   signature = K}, _Sig) ->
	      {#isis_tlv_authentication{type = md5,
					signature = <<0:(16*8)>>},
	       K};
	 (T, Sig) -> {T, Sig}
      end, missing_auth, TLVs).

verify_authentication_md5(_, _, missing_auth) ->
    missing_auth;
verify_authentication_md5(PDU, Key, Sig) ->
    case isis_protocol:md5sum(PDU, {md5, Key}) =:= Sig of
	true ->
	    valid;
	_ ->
	    invalid
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Flood a received LSP to other interfaces. Ultimately, this needs to be
%% maintained in the LSPDB so if we learn an LSP via multiple paths within
%5 quick succession, we don't flood unnecessarily...
%%
%% @end
%%--------------------------------------------------------------------
flood_lsp(LSP, #isis_pdu_state{circuit_name = Name,
			       level = Level}) ->
    Is = isis_system:list_circuits(),
    OutputIs = 
	lists:filter(
	  fun(#isis_circuit{name = N})
		when N =:= Name ->
		  false;
	     (_) -> true
	  end, Is),
    isis_lspdb:flood_lsp(Level, OutputIs, LSP, none).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Extract the database in a series of chunks ready to turn into CSNP
%% packets. We pace these out at a rate to avoid deludging the LAN.
%%
%% @end
%%--------------------------------------------------------------------
send_csnp(#isis_pdu_state{database = DBRef, dis_continuation = DC} = State) ->
    Args = case DC of
	       undef -> {start, 90};
	       _ -> {continue, DC}
	   end,
    {Summary, Continue} = isis_lspdb:summary(Args, DBRef),
    NextDC = 
	case generate_csnp(Args, 90, Summary, State) of
	    ok ->
		case Continue of
		    '$end_of_table' -> undef;
		    _ -> Continue
		end;
	    _ -> undef
	end,
    State#isis_pdu_state{dis_continuation = NextDC}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Take a series of LSP Detail summaries that have been extracted from
%% the database and package them up into TLVs and then place the TLVs
%% into the CSNP. We do a little work to calculate the start and end
%% lsp-id of this CSNP message.
%%
%% @end
%%--------------------------------------------------------------------
generate_csnp(_, _, _, #isis_pdu_state{system_id = SID}) when SID =:= undefined ->
    no_system_id;
generate_csnp({Status, _}, Chunk_Size, Summary,
	      #isis_pdu_state{system_id = Sys_ID, level = Level,
			     authentication = Auth,
			     level_authentication = LevelAuth,
			     parent = Parent,
			     parent_pid = Parent_pid} = State) ->
    Source = <<Sys_ID:6/binary, 0:8>>,
    PDU_Type =
	case Level of
	    level_1 -> level1_csnp;
	    level_2 -> level2_csnp
	end,
    {Start, End} = 
	case length(Summary) of
	    0 -> {<<255,255,255,255,255,255,255,255>>,
		  <<255,255,255,255,255,255,255,255>>};
	    _ ->
		%% If this is teh start, our 'first' lsp is all-zeros
		TStart =
		    case Status of
			start -> <<0,0,0,0,0,0,0,0>>;
			_ ->
			    %% Extract first LSP-ID
			    {SID, _, _, _} = lists:nth(1, Summary),
			    SID
		    end,
		%% If this is the end, all-ones
		TEnd = 
		    case  length(Summary) == Chunk_Size of
			true ->
			    %% Extract last LSP-ID
			    {LID, _, _, _} = lists:last(Summary),
			    LID;
			_ -> <<255,255,255,255,255,255,255,255>>
		    end,
		{TStart, TEnd}
	end,
    Details = lists:map(fun({ID, Seq, Check, Lifetime}) ->
				LF = case Lifetime > 0 of
					 true -> Lifetime;
					 _ -> 0
				     end,
				#isis_tlv_lsp_entry_detail{lsp_id = ID,
							   sequence = Seq,
							   checksum = Check,
							   lifetime = LF}
			end, Summary),
    DetailPackageFun = fun(F) -> [#isis_tlv_lsp_entry{lsps = F}] end,
    TLVs = isis_protocol:authentication_tlv(Auth)
	++ isis_protocol:package_tlvs(Details, DetailPackageFun,
				      ?LSP_ENTRY_DETAIL_PER_TLV),
    CSNP = #isis_csnp{pdu_type = PDU_Type,
		      source_id = Source,
		      start_lsp_id = Start,
		      end_lsp_id = End,
		      tlv = TLVs},
    isis_logger:debug("Sending CSNP: ~p", [CSNP]),
    {ok, PDU, PDU_Size} = isis_protocol:encode(CSNP, LevelAuth),
    Parent:send_pdu(Parent_pid, csnp, PDU, PDU_Size, Level),
    ok.
