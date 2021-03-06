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
%%% Created :  2 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_protocol).
-author("Rick Payne <rickp@rossfell.co.uk>").

-include("isis_protocol.hrl").
-include("isis_system.hrl").
-include_lib("eunit/include/eunit.hrl").

%% API
-export([decode/1, encode/2, checksum/1, md5sum/2,
	 package_tlvs/3,
	 current_timestamp/0, fixup_lifetime/1, filter_lifetime/1,
	 filter_tlvs/2,
	 update_tlv/4, create_new_frag/4,
	 authentication_tlv/1,
	 authentication_tlv_with_sig/2,
	 pp_tlv/1]).

%% For debugging...
-compile(export_all).

%% The types we define and use
-export_type([isis_pdu/0, isis_tlv/0,
	      isis_subtlv_eir/0, isis_subtlv_eis/0]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc decodes an ISIS PDU into erlang terms
%% Can decode LSPs for now
%% @end
%%--------------------------------------------------------------------
-spec decode(binary()) -> {ok, isis_pdu()} | error.
%% decode(Binary) when byte_size(Binary) >= ?ISIS_MIN_MSG_SIZE ->
%%     <<16#83:8, Len:8, Version:8, ID_Len:8,
%%     _Res1:3, PDU_Type:5, PDU_Version:8, _Res2:8,
%%     Max_Areas:8, Rest/binary>> = Binary,
decode(<<16#83:8, Len:8, Version:8, ID_Len:8,
	 _Res1:3, PDU_Type:5, PDU_Version:8, _Res2:8,
	 Max_Areas:8, Rest/binary>> = Binary)
  when byte_size(Binary) >= ?ISIS_MIN_MSG_SIZE ->
    Type = isis_enum:to_atom(pdu, PDU_Type),
    Header = #isis_header{
		header_length = Len,
		version = Version,
		id_length = ID_Len,
		pdu_type = Type,
		pdu_version = PDU_Version,
		maximum_areas = Max_Areas},
    decode_pdu(Type, Header, byte_size(Binary), Rest).

%%--------------------------------------------------------------------
%% @doc encode a set of IS-IS terms into a PDU
%% @end
%%--------------------------------------------------------------------
-spec encode(isis_pdu(), [atom() | tuple()]) -> {ok, list(), integer()} | error.
encode(#isis_iih{} = IIH, Crypto) ->
    encode_iih(IIH, Crypto);
encode(#isis_p2p_iih{} = IIH, Crypto) ->
     encode_p2p_iih(IIH, Crypto);
encode(#isis_lsp{} = LSP, Crypto) ->
    encode_lsp(LSP, Crypto);
encode(#isis_csnp{} = CSNP, Crypto) ->
    encode_csnp(CSNP, Crypto);
encode(#isis_psnp{} = PSNP, Crypto) ->
    encode_psnp(PSNP, Crypto).

%%--------------------------------------------------------------------
%% @doc encode a set of IS-IS terms into a PDU
%% @end
%%--------------------------------------------------------------------
-spec package_tlvs(list(), fun(), integer()) -> list().
package_tlvs(TLVs, PackageFun, Count) ->
     package_tlvs(TLVs, PackageFun, Count, []).

package_tlvs(TLVs, PackageFun, Count, Acc)
  when length(TLVs) > Count ->
    {Head, Tail} = lists:split(Count, TLVs),
    Package = PackageFun(Head),
    package_tlvs(Tail, PackageFun, Count, Package ++ Acc);
package_tlvs([], _PackageFun, _Count, Acc) ->
    lists:reverse(Acc);
package_tlvs(TLVs, PackageFun, _Count, Acc) ->
    Package = PackageFun(TLVs),
    lists:reverse(Package ++ Acc).

%%--------------------------------------------------------------------
%% @doc Filter a set of TLVs to include only the ones in the
%% provided. You can filter for an individual TLV (and get back a set
%% of TLVs that match) or a list.  @end
%% --------------------------------------------------------------------
filter_tlvs(AcceptedTLV, TLVs) when is_atom(AcceptedTLV) ->
    [X || X <- TLVs, element(1, X) =:= AcceptedTLV];
filter_tlvs(AcceptedTLVs, TLVs) ->
    F = fun(T) -> lists:member(element(1, T), AcceptedTLVs) end,
    lists:filter(F, TLVs).
	  

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%%===================================================================
%%% TLV and subTLV decoders
%%%===================================================================
-spec decode_subtlv_ipv6r(atom(), integer(), binary()) -> isis_subtlv_ipv6r() | error.
decode_subtlv_ipv6r(source_prefix, _Type, <<PLen:8, P/binary>>) ->
    Bytes = erlang:trunc((PLen + 7) / 8),
    case byte_size(P) =:= Bytes of
	true -> #isis_subtlv_srcdst{prefix_length = PLen, prefix = P};
	_ -> throw(decode_error)
    end;
decode_subtlv_ipv6r(_, Type, Value) ->
    #isis_subtlv_unknown{type = Type, value = Value}.

-spec decode_subtlv_eir(atom(), integer(), binary()) -> isis_subtlv_eir() | error.
decode_subtlv_eir(admin_tag_32bit, _Type, <<Value:32>>) ->
    #isis_subtlv_eir_admintag32{tag = Value};
decode_subtlv_eir(admin_tag_64bit, _Type, <<Value:64>>) ->
    #isis_subtlv_eir_admintag64{tag = Value}.

-spec decode_subtlv_eis(atom(), integer(), binary()) -> isis_subtlv_eis() | error.
decode_subtlv_eis(link_id, _Type, <<Local:32, Remote:32>>) ->
    #isis_subtlv_eis_link_id{local = Local, remote = Remote};
decode_subtlv_eis(ipv4_interface, _Type, <<IP:32>>) ->
    #isis_subtlv_eis_ipv4_interface{address = IP};
decode_subtlv_eis(_, Type, Value) ->
    #isis_subtlv_unknown{type = Type, value = Value}.

-spec decode_tlv_area_address(binary(), [binary()]) -> [binary()] | error.
decode_tlv_area_address(<<>>, Areas) ->
    lists:reverse(Areas);
decode_tlv_area_address(<<Len:8, Area:Len/binary, Rest/binary>>, Areas) ->
    decode_tlv_area_address(Rest, [Area | Areas]).

-spec decode_tlv_is_reachability(binary(), [isis_tlv_is_reachability_detail()]) ->
					[isis_tlv_is_reachability_detail()] | error.
decode_tlv_is_reachability(<<Default:1/binary, Delay:1/binary,
			     Expense:1/binary, Error:1/binary,
			     Neighbor_Id:7/binary, Rest/binary>>, Neighbors) ->
    DefaultM = decode_isis_metric_information(Default, default),
    DelayM = decode_isis_metric_information(Delay, false),
    ExpenseM = decode_isis_metric_information(Expense, false),
    ErrorM = decode_isis_metric_information(Error, false),
    IR = #isis_tlv_is_reachability_detail{neighbor = Neighbor_Id,
					  default = DefaultM, delay = DelayM,
					  expense = ExpenseM, error = ErrorM},
    decode_tlv_is_reachability(Rest, [IR | Neighbors]);
decode_tlv_is_reachability(<<>>, Neighbors) ->
    lists:reverse(Neighbors).

-spec decode_tlv_lsp_entry(binary(), [isis_tlv_lsp_entry_detail()]) ->
				  [isis_tlv_lsp_entry_detail()] | error.
decode_tlv_lsp_entry(<<>>, LSPs) ->
    lists:reverse(LSPs);
decode_tlv_lsp_entry(<<Lifetime:16, LSP_Id:8/binary,
		       Sequence:32, Checksum:16, Rest/binary>>, LSPs) ->
    decode_tlv_lsp_entry(Rest, [#isis_tlv_lsp_entry_detail{
				   lsp_id = LSP_Id,
				   lifetime = Lifetime,
				   sequence = Sequence,
				   checksum = Checksum}
				| LSPs]).

-spec decode_isis_metric_information(binary(), atom())
			       -> isis_metric_information().
decode_isis_metric_information(<<0:1, B7:1, Metric:6>>, default) ->
    #isis_metric_information{metric_supported = true,
			     metric_type = isis_enum:to_atom(metric_type, B7),
			     metric = Metric};
decode_isis_metric_information(<<B8:1, B7:1, Metric:6>>, Type) when
      Type /= default ->
    Supported = isis_enum:to_atom(boolean, B8),
    #isis_metric_information{metric_supported = Supported,
			     metric_type = isis_enum:to_atom(metric_type, B7),
			     metric = Metric}.

-spec decode_tlv_ip_internal_reachability(binary(),
					  [isis_tlv_ip_internal_reachability_detail()])
					 -> [isis_tlv_ip_internal_reachability_detail()] | error.
decode_tlv_ip_internal_reachability(<<Default:1/binary, Delay:1/binary,
				      Expense:1/binary, Error:1/binary,
				      IP_Address:32, Subnet_Mask:32,
				      Rest/binary>>, Values) ->
    DefaultM = decode_isis_metric_information(Default, default),
    DelayM = decode_isis_metric_information(Delay, false),
    ExpenseM = decode_isis_metric_information(Expense, false),
    ErrorM = decode_isis_metric_information(Error, false),
    MI = #isis_tlv_ip_internal_reachability_detail{
	    ip_address = IP_Address,
	    subnet_mask = Subnet_Mask,
	    default = DefaultM,
	    delay = DelayM,
	    expense = ExpenseM,
	    error = ErrorM},
    decode_tlv_ip_internal_reachability(Rest,
					[MI | Values]);
decode_tlv_ip_internal_reachability(<<>>, Values) ->
    lists:reverse(Values).

decode_tlv_extended_ip_reachability(
  <<Metric:32, Up:1, SubTLV_Present:1, Mask_Len:6, Rest/binary>>, Values) ->
    %%% Mask_Len -> whole bytes then we shift the extracted value
    PLenBytes = erlang:trunc((Mask_Len + 7) / 8),
    PLenBits = PLenBytes * 8,
    <<P1:PLenBits, Rest2/binary>> = Rest,
    Prefix = P1 bsl (32 - PLenBits),
    {SubTLV, Rest4} =
	case SubTLV_Present of
	    0 -> {[], Rest2} ;
	    1 ->
		<<SubTLV_Len:8, SubTLVb:SubTLV_Len/binary, Rest3/binary>> = Rest2,
		{ok, STLVs} = {decode_tlvs(SubTLVb, subtlv_eir, fun decode_subtlv_eir/3, []), Rest3},
		{STLVs, Rest3}
	end,
    UpA = isis_enum:to_atom(boolean, 1 - Up),
    EIR = #isis_tlv_extended_ip_reachability_detail{
	     prefix = Prefix,
	     mask_len = Mask_Len,
	     metric = Metric,
	     up = UpA,
	     sub_tlv = SubTLV},
    decode_tlv_extended_ip_reachability(Rest4, [EIR | Values]);
decode_tlv_extended_ip_reachability(<<>>, Values) ->
    lists:reverse(Values).

decode_tlv_ipv6_reachability(<<Metric:32, Up:1, X:1, S:1,
			       _Res:5, PLen:8, Rest/binary>>, Acc) ->
    PLenBytes = erlang:trunc((PLen + 7) / 8),
    {Prefix, SubTLVs, Remainder} = 
	case S of
	    1 ->
		<<P:PLenBytes/binary, SLen:8, SubTLVBytes:SLen/binary, R/binary>> = Rest,
		{ok, STs} = decode_tlvs(SubTLVBytes, subtlv_ipv6r,
					    fun decode_subtlv_ipv6r/3, []),
		{P, STs, R};
	    0 ->
		<<P:PLenBytes/binary, R/binary>> = Rest,
		{P, [], R}
	end,
    decode_tlv_ipv6_reachability(Remainder,
				 [#isis_tlv_ipv6_reachability_detail{metric = Metric,
								     up = isis_enum:to_atom(boolean, 1 - Up),
								     external = isis_enum:to_atom(boolean, X),
								     mask_len = PLen,
								     prefix = Prefix,
								     sub_tlv = SubTLVs} | Acc]);
decode_tlv_ipv6_reachability(<<>>, Acc) ->
    lists:reverse(Acc).

decode_tlv_extended_reachability(
  <<Neighbor_Id:7/binary, Metric:24,
    SubTLV_Len:8, SubTLVb:SubTLV_Len/binary, Rest/binary>>, Values) ->
    case decode_tlvs(SubTLVb, subtlv_eis, fun decode_subtlv_eis/3, []) of
	{ok, SubTLVs} ->
	    EIS = #isis_tlv_extended_reachability_detail{
		     neighbor = Neighbor_Id,
		     metric = Metric,
		     sub_tlv = SubTLVs},
	    decode_tlv_extended_reachability(Rest, [EIS | Values]);
	_ -> throw(decode_error)
    end;    
decode_tlv_extended_reachability(<<>>, Values) ->
    lists:reverse(Values).



%%--------------------------------------------------------------------
%% @doc Convert a binary TLV into a record of the appropriate type,
%% or an 'unknown tlv' which can be re-encoded later
%% @end
%%--------------------------------------------------------------------
-spec decode_tlv(atom(), integer(), binary()) -> isis_tlv().
decode_tlv(area_address, _Type, Value) ->
    Areas = decode_tlv_area_address(Value, []),
    #isis_tlv_area_address{areas = Areas};
decode_tlv(is_neighbors, _Type, Value) ->
    Neighbors = [X || <<X:6/binary>> <= Value],
    #isis_tlv_is_neighbors{neighbors = Neighbors};
decode_tlv(is_reachability, _Type, <<Virtual:8, Rest/binary>>) ->
    VirtualA = isis_enum:to_atom(boolean, Virtual),
    Neighbors = decode_tlv_is_reachability(Rest, []),
    #isis_tlv_is_reachability{virtual = VirtualA,
			      is_reachability = Neighbors};
decode_tlv(padding, _Type, Value) ->
    #isis_tlv_padding{size = byte_size(Value)};
decode_tlv(lsp_entry, _Type, Value) ->
    LSPs = decode_tlv_lsp_entry(Value, []),
    #isis_tlv_lsp_entry{lsps = LSPs};
decode_tlv(authentication, _Type, <<AuthType:8, Rest/binary>> = R) ->
    try isis_enum:to_atom(authentication_type, AuthType) of
	AT -> 
	    #isis_tlv_authentication{type = AT, signature = Rest}
    catch
	bad_enum -> #isis_tlv_authentication{type = unknown,
					     signature = R}
    end;
decode_tlv(dynamic_hostname, _Type, Value) ->
    #isis_tlv_dynamic_hostname{hostname = binary:bin_to_list(Value)};
decode_tlv(ip_internal_reachability, _Type, Value) ->
    Reachability = decode_tlv_ip_internal_reachability(Value, []),
    #isis_tlv_ip_internal_reachability{ip_reachability = Reachability};
decode_tlv(extended_ip_reachability, _Type, Value) ->
    EIR = decode_tlv_extended_ip_reachability(Value, []),
    #isis_tlv_extended_ip_reachability{reachability = EIR};
decode_tlv(extended_reachability, _Type, Value) ->
    EIS = decode_tlv_extended_reachability(Value, []),
    #isis_tlv_extended_reachability{reachability = EIS};
decode_tlv(ip_interface_address, _Type, Value) ->
    Addresses = [X || <<X:32>> <= Value],
    #isis_tlv_ip_interface_address{addresses = Addresses};
decode_tlv(ipv6_interface_address, _Type, Value) ->
    Addresses = [X || <<X:16/binary>> <= Value],
    #isis_tlv_ipv6_interface_address{addresses = Addresses};
decode_tlv(ipv6_reachability, _Type, Bytes) ->
    Reachability = decode_tlv_ipv6_reachability(Bytes, []),
    #isis_tlv_ipv6_reachability{reachability = Reachability};
decode_tlv(protocols_supported, _Type, Value) ->
    Protocols = [isis_enum:to_atom(protocols, X) || <<X:8>> <= Value],
    #isis_tlv_protocols_supported{protocols = Protocols};
decode_tlv(te_router_id, _Type, <<Router_Id:32>>) ->
    #isis_tlv_te_router_id{router_id = Router_Id};
decode_tlv(p2p_adjacency_state, _Type,
	   <<State:8, LocalCircuit:32, SysID:6/binary, NeighborCircuit:32>>) ->
    #isis_tlv_p2p_adjacency_state{
       state = isis_enum:to_atom(p2p_state, State),
       local_circuit = LocalCircuit,
       neighbor = SysID,
       neighbor_circuit = NeighborCircuit};
%% decode_tlv(restart, _Type,
%% 	   <<_Res:5, Supress:1, Ack:1, Restart:1>>) ->
%%     #isis_tlv_restart{
%%        request = isis_enum:to_atom(boolean, Restart),
%%        acknowledge = isis_enum:to_atom(boolean, Ack),
%%        supress_adjacency = isis_enum:to_atom(boolean, Supress),
%%        remaining = -1,
%%        neighbor = <<>>};
%% decode_tlv(restart, _Type,
%% 	   <<_Res:5, Supress:1, Ack:1, Restart:1, Remaining:16>>) ->
%%     #isis_tlv_restart{
%%        request = isis_enum:to_atom(boolean, Restart),
%%        acknowledge = isis_enum:to_atom(boolean, Ack),
%%        supress_adjacency = isis_enum:to_atom(boolean, Supress),
%%        remaining = Remaining,
%%        neighbor = <<>>};
%% decode_tlv(restart, _Type,
%% 	   <<_Res:5, Supress:1, Ack:1, Restart:1, Remaining:16, Neighbor:6/binary>>) ->
%%     #isis_tlv_restart{
%%        request = isis_enum:to_atom(boolean, Restart),
%%        acknowledge = isis_enum:to_atom(boolean, Ack),
%%        supress_adjacency = isis_enum:to_atom(boolean, Supress),
%%        remaining = Remaining,
%%        neighbor = Neighbor};
decode_tlv(geninfo, _Type,
	   <<_Reserved:4, 0:1, 1:1, D:1, S:1, AppID:16, Ip:32, AppGunk/binary>>) ->
    #isis_tlv_geninfo{
       d_bit = isis_enum:to_atom(boolean, D),
       s_bit = isis_enum:to_atom(boolean, S),
       application_id = AppID,
       application_ip_address = #isis_address{afi = ipv4, address = Ip},
       application_gunk = AppGunk
      };
decode_tlv(geninfo, _Type,
	   <<_Reserved:4, 1:1, 0:1, D:1, S:1, AppID:16, Ip:16/binary, AppGunk/binary>>) ->
    #isis_tlv_geninfo{
       d_bit = isis_enum:to_atom(boolean, D),
       s_bit = isis_enum:to_atom(boolean, S),
       application_id = AppID,
       application_ip_address = #isis_address{afi = ipv6, address = Ip},
       application_gunk = AppGunk
      };
decode_tlv(geninfo, _Type,
	   <<_Reserved:4, 0:1, 0:1, D:1, S:1, AppID:16, AppGunk/binary>>) ->
    #isis_tlv_geninfo{
       d_bit = isis_enum:to_atom(boolean, D),
       s_bit = isis_enum:to_atom(boolean, S),
       application_id = AppID,
       application_ip_address = undefined,
       application_gunk = AppGunk
      };
decode_tlv(hardware_fingerprint, _Type, <<FP/binary>>) ->
    #isis_tlv_hardware_fingerprint{fingerprint = FP};
decode_tlv(unknown, Type, Value) ->
    #isis_tlv_unknown{type = Type, bytes = Value};

decode_tlv(_, Type, Value) ->
    decode_tlv(unknown, Type, Value).

-spec decode_tlvs(binary(), atom(), fun(), [isis_tlv()]) -> {ok, [isis_tlv()]} | error.
decode_tlvs(<<>>, _Enum, _Fun, TLVs) ->
    {ok, lists:reverse(TLVs)};
decode_tlvs(<<Type:8, Length:8, Value:Length/binary, Rest/binary>>,
	    Enum, TLVDecode, TLVs) ->
    TLV_Type = 
	try isis_enum:to_atom(Enum, Type) of
	    Atom -> Atom
	catch
	    bad_enum -> unknown
	end,
    %% isis_logger:info("Decoding TLV: ~p", [<<Type:8, Length:8, Value/binary>>]),
    case TLVDecode(TLV_Type, Type, Value) of
	error -> throw(decode_error);
	TLV ->
	    decode_tlvs(Rest, Enum, TLVDecode, [TLV | TLVs])
    end.


%%%===================================================================
%%% TLV and subTLV encoders
%%%===================================================================
-spec encode_subtlv_ipv6r(isis_subtlv_ipv6r()) -> binary().
encode_subtlv_ipv6r(#isis_subtlv_srcdst{prefix_length = PL, prefix = P}) when is_binary(P) ->
    encode_tlv(source_prefix, subtlv_ipv6r, <<PL:8, P/binary>>);
encode_subtlv_ipv6r(#isis_subtlv_srcdst{prefix_length = PL, prefix = P}) when is_integer(P) ->
    Bits = (erlang:trunc((PL + 7) / 8) * 8),
    P1 = P bsr (128 - Bits),
    encode_tlv(source_prefix, subtlv_ipv6r, <<PL:8, P1:Bits>>);
encode_subtlv_ipv6r(#isis_subtlv_unknown{type = T, value = V}) ->
    S = byte_size(V),
    <<T:8, S:8, V/binary>>.

-spec encode_subtlv_eir_detail(isis_subtlv_eir()) -> binary().
encode_subtlv_eir_detail(#isis_subtlv_eir_admintag32{tag = Tag}) ->
    Type = isis_enum:to_int(subtlv_eir, admin_tag_32bit),
    <<Type:8, 4:8, Tag:32>>;
encode_subtlv_eir_detail(#isis_subtlv_eir_admintag64{tag = Tag}) ->
    Type = isis_enum:to_int(subtlv_eir, admin_tag_64bit),
    <<Type:8, 8:8, Tag:64>>.

encode_subtlv_eis_detail(#isis_subtlv_eis_link_id{local = Local,
						  remote = Remote}) ->
    encode_tlv(link_id, subtlv_eis, <<Local:32, Remote:32>>);
encode_subtlv_eis_detail(#isis_subtlv_eis_ipv4_interface{address = Address}) ->
    encode_tlv(ipv4_interface, subtlv_eis, <<Address:32>>);
encode_subtlv_eis_detail(#isis_subtlv_unknown{type = Type, value = Value}) ->
    S = byte_size(Value),
    [<<Type:8, S:8, Value/binary>>].
			
-spec encode_tlv_area_address([binary()], binary()) -> binary().
encode_tlv_area_address([A | As], B) ->
    S = byte_size(A),
    encode_tlv_area_address(As, <<B/binary, S:8, A/binary>>);
encode_tlv_area_address([], B) ->
    B.

-spec encode_tlv_is_reachability(isis_tlv_is_reachability_detail()) -> binary().
encode_tlv_is_reachability(
  #isis_tlv_is_reachability_detail{neighbor = Neighbor,
				   default = Default,
				   delay = Delay,
				   expense = Expense,
				   error = Error}) ->
    DefaultB = encode_tlv_metric_info(default, Default),
    DelayB = encode_tlv_metric_info(false, Delay),
    ExpenseB = encode_tlv_metric_info(false, Expense),
    ErrorB = encode_tlv_metric_info(false, Error),
    <<DefaultB/binary, DelayB/binary, ExpenseB/binary,
      ErrorB/binary, Neighbor/binary>>.

-spec encode_tlv_metric_info(atom(), isis_metric_information()) -> binary().
encode_tlv_metric_info(default,
		       #isis_metric_information{metric = Metric,
						metric_type = Metric_Type}) ->
    MT = isis_enum:to_int(metric_type, Metric_Type),
    <<0:1, MT:1, Metric:6>>;
encode_tlv_metric_info(false,
		       #isis_metric_information{metric_supported = Support,
						metric = Metric,
						metric_type = Metric_Type}) ->
    ST = isis_enum:to_int(boolean, Support),
    MT = isis_enum:to_int(metric_type, Metric_Type),
    <<ST:1, MT:1, Metric:6>>.

-spec encode_tlv_ip_internal_reachability(isis_tlv_ip_internal_reachability_detail()) -> binary().
encode_tlv_ip_internal_reachability(
  #isis_tlv_ip_internal_reachability_detail{ip_address = IP_Address,
					    subnet_mask = Subnet_Mask,
					    default = Default,
					    delay = Delay,
					    expense = Expense,
					    error = Error}) ->
    DefaultB = encode_tlv_metric_info(default, Default),
    DelayB = encode_tlv_metric_info(false, Delay),
    ExpenseB = encode_tlv_metric_info(false, Expense),
    ErrorB = encode_tlv_metric_info(false, Error),
    <<DefaultB/binary, DelayB/binary,
      ExpenseB/binary, ErrorB/binary,
      IP_Address:32, Subnet_Mask:32>>.

-spec encode_tlv_extended_ip_reachability(isis_tlv_extended_ip_reachability_detail()) -> [binary()].
encode_tlv_extended_ip_reachability(
  #isis_tlv_extended_ip_reachability_detail{
     prefix = Prefix, mask_len = Mask_Len,
     metric = Metric, up = UpA,
     sub_tlv = SubTLVs}) ->
    SubTLVB = encode_tlvs(SubTLVs, fun encode_subtlv_eir_detail/1),
    SubTLV_Len = binary_list_size(SubTLVB),
    {Present, SubTLV_LenB} = 
	case SubTLV_Len of
	    0 -> {0, <<>>};
	    _ -> {1, <<SubTLV_Len:8>>}
	end,
    %%% Mask_Len -> whole bytes, then we shift to lineup
    PLenBytes = erlang:trunc((Mask_Len + 7) / 8),
    PLenBits = PLenBytes * 8,
    Calc_Prefix = Prefix bsr (32 - PLenBits),
    Up = 1 - isis_enum:to_int(boolean, UpA),
    [<<Metric:32, Up:1, Present:1, Mask_Len:6,
      Calc_Prefix:PLenBits, SubTLV_LenB/binary>> | SubTLVB].

encode_tlv_ipv6_reachability_detail(
  #isis_tlv_ipv6_reachability_detail{
     metric = Metric, up = Up, external = External,
     mask_len = Mask_Len, prefix = Prefix,
     sub_tlv = Sub_TLVs}) ->
    U = 1 - isis_enum:to_int(boolean, Up),
    E = isis_enum:to_int(boolean, External),
    PBytes = erlang:trunc((Mask_Len + 7) / 8),
    {P, SLen, SBin}
	= case length(Sub_TLVs) of
	      0 -> {0, <<>>, []};
	    _ ->
		  SBinary = encode_tlvs(Sub_TLVs, fun encode_subtlv_ipv6r/1),
		  SBinaryLen = binary_list_size(SBinary),
		  {1, <<SBinaryLen:8>>, SBinary}
	  end,
    [<<Metric:32, U:1, E:1, P:1, 0:5,
       Mask_Len:8, Prefix:PBytes/binary, SLen/binary>> | SBin].

-spec encode_tlv_extended_reachability(isis_tlv_extended_reachability_detail()) -> [binary()].
encode_tlv_extended_reachability(
  #isis_tlv_extended_reachability_detail{
     neighbor = Neighbor_Id,
     metric = Metric,
     sub_tlv = SubTLVs}) ->
    SubTLVB = encode_tlvs(SubTLVs, fun encode_subtlv_eis_detail/1),
    SubTLV_Len = binary_list_size(SubTLVB),
    [<<Neighbor_Id:7/binary, Metric:24, SubTLV_Len:8>> | SubTLVB].

-spec encode_tlv_lsp_entry(isis_tlv_lsp_entry_detail()) -> binary().
encode_tlv_lsp_entry(
  #isis_tlv_lsp_entry_detail{lifetime = Lifetime,
			     lsp_id = LSP_Id,
			     sequence = Sequence,
			     checksum = Checksum}) -> 
    <<Lifetime:16, LSP_Id:8/binary, Sequence:32, Checksum:16>>.

-spec encode_tlv(isis_tlv()) -> [binary()].
encode_tlv(#isis_tlv_area_address{areas = Areas}) ->
    encode_tlv(area_address, tlv, encode_tlv_area_address(Areas, <<>>));
encode_tlv(#isis_tlv_is_reachability{virtual = VirtualA,
				     is_reachability = Neighbors}) ->
    Virtual = isis_enum:to_int(boolean, VirtualA),
    Ns = lists:map(fun encode_tlv_is_reachability/1, Neighbors),
    encode_tlv_list(is_reachability, tlv, [<<Virtual:8>>, Ns]);
encode_tlv(#isis_tlv_is_neighbors{neighbors = []}) ->
    [];
encode_tlv(#isis_tlv_is_neighbors{neighbors = Neighbors}) ->
    encode_tlv_list(is_neighbors, tlv, Neighbors);
encode_tlv(#isis_tlv_padding{size = Size}) ->
    encode_tlv(padding, tlv, <<0:(Size * 8)>>);
encode_tlv(#isis_tlv_lsp_entry{lsps = LSPS}) ->
    LSPb = lists:map(fun encode_tlv_lsp_entry/1, LSPS),
    encode_tlv_list(lsp_entry, tlv, LSPb);
encode_tlv(#isis_tlv_authentication{type = unknown}) ->
    [];
encode_tlv(#isis_tlv_authentication{type = md5, signature = S,
				    do_not_rewrite = DNR}) ->
    AuthType = isis_enum:to_int(authentication_type, md5),
    case DNR of
	true ->
	    encode_tlv(authentication, tlv, <<AuthType:8, S/binary>>);
	_ ->
	    %% Stuff a place holder in, so we can find where to insert the signature later
	    {md5_signature, encode_tlv(authentication, tlv, <<AuthType:8, 0:(16*8)>>)}
    end;
encode_tlv(#isis_tlv_authentication{type = AT, signature = Sig}) ->
    AuthType = isis_enum:to_int(authentication_type, AT),
    encode_tlv(authentication, tlv, <<AuthType:8, Sig/binary>>);
encode_tlv(#isis_tlv_ip_internal_reachability{ip_reachability = IP_Reachability}) ->
    IP_Rb = lists:map(fun encode_tlv_ip_internal_reachability/1, IP_Reachability),
    encode_tlv_list(ip_internal_reachability, tlv, IP_Rb);
encode_tlv(#isis_tlv_dynamic_hostname{hostname = Hostname}) ->
    encode_tlv(dynamic_hostname, tlv, binary:list_to_bin(Hostname));
%% encode_tlv(#isis_tlv_restart{request = Req, acknowledge = Ack,
%% 			     supress_adjacency = SA, remaining = Remaining,
%% 			     neighbor = N}) ->
%%     ReqI = isis_enum:to_int(boolean, Req),
%%     AckI = isis_enum:to_int(boolean, Ack),
%%     SAI = isis_enum:to_int(boolean, SA),
%%     encode_tlv(restart, tlv, <<0:5, SAI:1, AckI:1, ReqI:1>>);
encode_tlv(#isis_tlv_ip_interface_address{addresses = Addresses}) ->
    As = lists:map(fun(A) -> <<A:32>> end, Addresses),
    encode_tlv_list(ip_interface_address, tlv, As);
encode_tlv(#isis_tlv_extended_ip_reachability{reachability = EIR}) ->
    Bs = lists:map(fun encode_tlv_extended_ip_reachability/1, EIR),
    encode_tlv_list(extended_ip_reachability, tlv, Bs);
encode_tlv(#isis_tlv_ipv6_interface_address{addresses = Addresses}) ->
    %% Takes either binary or integer addresses...
    Bs = lists:map(fun(B) when is_integer(B) ->
			   <<B:(16*8)>>;
		      (B) when is_binary(B) ->
			   <<B:16/binary>>
		   end,
		   Addresses),
    encode_tlv_list(ipv6_interface_address, tlv, Bs);
encode_tlv(#isis_tlv_ipv6_reachability{reachability = []}) ->
    [];
encode_tlv(#isis_tlv_ipv6_reachability{reachability = R}) ->
    Bs = lists:map(fun encode_tlv_ipv6_reachability_detail/1, R),
    encode_tlv_list(ipv6_reachability, tlv, Bs);
encode_tlv(#isis_tlv_extended_reachability{reachability = EIS}) ->
    Bs = lists:map(fun encode_tlv_extended_reachability/1, EIS),
    encode_tlv_list(extended_reachability, tlv, Bs);
encode_tlv(#isis_tlv_protocols_supported{protocols = Protocols}) ->
    Ps = lists:map(fun(A) -> At = isis_enum:to_int(protocols, A),
			     <<At:8>> end, Protocols),
    encode_tlv_list(protocols_supported, tlv, Ps);
encode_tlv(#isis_tlv_te_router_id{router_id = Router_Id}) ->
    encode_tlv(te_router_id, tlv, <<Router_Id:32>>);
encode_tlv(#isis_tlv_p2p_adjacency_state{state = S,
					 local_circuit = LC,
					 neighbor = N,
					 neighbor_circuit = NC}) ->
    State = isis_enum:to_int(p2p_state, S),
    encode_tlv(p2p_adjacnecy_state, tlv, <<State:8, LC:32, N:6/binary, NC:32>>);
encode_tlv(#isis_tlv_geninfo{d_bit = D, s_bit = S,
			     application_id = AppID,
			     application_ip_address = AppAddress,
			     application_gunk = AppGunk}) ->
    {AFlags, Address} = 
	case AppAddress of
	    undefined -> {<<0:2>>, <<>>};
	    #isis_address{afi = AFI,
			  address = Addr} ->
		case AFI of
		    ipv4 -> {<<0:1, 1:1>>, <<Addr:32>>};
		    ipv6 -> {<<1:1, 0:1>>, Addr}
		end
	end,
    Flags = <<0:4, AFlags/bitstring, (isis_enum:to_int(boolean, D)):1, (isis_enum:to_int(boolean, S)):1>>,
    encode_tlv(geninfo, tlv, <<Flags/bitstring, AppID:16, Address/binary, AppGunk/binary>>);
encode_tlv(#isis_tlv_hardware_fingerprint{fingerprint = FP}) ->
    encode_tlv(hardware_fingerprint, tlv, FP);
encode_tlv(#isis_tlv_unknown{type = Type, bytes = Bytes}) ->
    S = byte_size(Bytes),
    [<<Type:8, S:8, Bytes/binary>>];
encode_tlv(_) ->
    <<>>.

-spec encode_tlv(atom(), atom(), binary()) -> [binary()].
encode_tlv(Type, Enum, Value) ->
    T = isis_enum:to_int(Enum, Type),
    S = byte_size(Value),
    [<<T:8, S:8, Value/binary>>].


-spec encode_tlv_list(atom(), atom(), [binary()]) -> [binary()].
encode_tlv_list(Type, Enum, Values) ->
    S = binary_list_size(Values),
    T = isis_enum:to_int(Enum, Type),
    [<<T:8, S:8>>] ++ [Values].

-spec encode_tlvs(list(), fun()) -> [binary()].
encode_tlvs(TLVs, Encoder) ->
    lists:map(Encoder, TLVs).

%%%===================================================================
%%% TLV sizing
%%% ===================================================================


%%%===================================================================
%%% TLV updating
%%% ===================================================================
do_update_tlv(#isis_tlv_is_reachability{} = TLV, 
	   Node, Level, Frags) ->
    merge_array_tlv(TLV, Node, Level, Frags);
do_update_tlv(#isis_tlv_extended_reachability{} = TLV, 
	   Node, Level, Frags) ->
    merge_array_tlv(TLV, Node, Level, Frags);
do_update_tlv(#isis_tlv_dynamic_hostname{} = TLV,
	  Node, Level, Frags) ->
    F = fun(T) -> element(1, T) =/= element(1, TLV) end,
    merge_whole_tlv(F, TLV, Node, Level, Frags);
do_update_tlv(#isis_tlv_ipv6_reachability{} = TLV,
	   Node, Level, Frags) ->
    merge_array_tlv(TLV, Node, Level, Frags);
do_update_tlv(#isis_tlv_ip_internal_reachability{} = TLV,
	   Node, Level, Frags) ->
    merge_array_tlv(TLV, Node, Level, Frags);
do_update_tlv(#isis_tlv_extended_ip_reachability{} = TLV,
	   Node, Level, Frags) ->
    merge_array_tlv(TLV, Node, Level, Frags);
%% Default merge..
do_update_tlv(TLV, Node, Level, Frags) ->
    F = fun(T) -> element(1, T) =/= element(1, TLV) end,
    merge_whole_tlv(F, TLV, Node, Level, Frags).
update_tlv(TLV, Node, Level, Frags) ->
    {TLVName, TLVDetails} = pp_tlv(TLV),
    isis_logger:warning("Updating TLV for ~p PN ~B: ~s: ~s",
		  [Level, Node, TLVName, TLVDetails]),
    try do_update_tlv(TLV, Node, Level, Frags) of
	F -> F
    catch
	Class:Error -> isis_logger:error("update_tlv: ~p:~p", [Class, Error]),
		       Frags
    end.


do_delete_tlv(#isis_tlv_dynamic_hostname{} = TLV,
	   Node, Level, Frags) ->
    delete_whole_tlv(fun(T) -> element(1, T) =/= element(1, TLV) end,
		     Node, Level, Frags);
do_delete_tlv(#isis_tlv_is_reachability{} = TLV,
	   Node, Level, Frags) ->
    delete_array_tlv(TLV, Node, Level, Frags);
do_delete_tlv(#isis_tlv_extended_reachability{} = TLV,
	   Node, Level, Frags) ->
    delete_array_tlv(TLV, Node, Level, Frags);
do_delete_tlv(#isis_tlv_extended_ip_reachability{} = TLV,
	   Node, Level, Frags) ->
    delete_array_tlv(TLV, Node, Level, Frags);
do_delete_tlv(#isis_tlv_ipv6_reachability{} = TLV,
	   Node, Level, Frags) ->
    delete_array_tlv(TLV, Node, Level, Frags);
do_delete_tlv(#isis_tlv_geninfo{} = TLV,
	      Node, Level, Frags) ->
    delete_whole_tlv(fun(T) -> T =/= TLV end,
		     Node, Level, Frags);
do_delete_tlv(TLV, Node, Level, Frags) ->
    delete_whole_tlv(fun(T) -> element(1, T) =/= element(1, TLV) end,
		     Node, Level, Frags).
delete_tlv(TLV, Node, Level, Frags) ->
    %% isis_logger:warning("Deleting TLV for ~p PN ~B: ~p",
    %%	  [Level, Node, isis_logger:pr(TLV, ?MODULE)]),
    try do_delete_tlv(TLV, Node, Level, Frags) of
	F -> F
    catch
	Class:Error -> isis_logger:info("delete_tlv: ~p:~p", [Class, Error]),
		       Frags
    end.	     



%%%===================================================================
%%% TLV merge / split functions
%%% ===================================================================
%%% ===================================================================
%%% delete_whole_tlv - delete a TLV where the matcher function returns
%%% true
%%% ===================================================================
-spec delete_whole_tlv(fun(), integer(), atom(), [lsp_frag()]) -> [lsp_frag()].
delete_whole_tlv(MatchFun, Node, Level, Frags) ->
    Delete = fun(T) -> MatchFun(T) end,
    Iterator = fun(#lsp_frag{pseudonode = N, level = L, tlvs = TLVs} = F)
		    when N =:= Node, L =:= Level ->
		       NewTLVs = lists:filter(Delete, TLVs),
		       case length(NewTLVs) =:= length(TLVs) of
			   false ->
			       isis_system:schedule_lsp_refresh(),
			       F#lsp_frag{updated = true,
					  size = tlv_size(NewTLVs),
					  tlvs = NewTLVs};
			   _ ->
			       F
		       end;
		  (F) -> F
	       end,
    NewFrags = lists:map(Iterator, Frags),
    NewFrags.

%%% ===================================================================
%%% delete_array_tlv - delete an entry from an arrayed TLV
%%% ===================================================================
delete_array_tlv(TLV, Node, Level, Frags) ->
    TLVType = element(1, TLV),
    Deleter = fun(T, {_, Size}) when element(1, T) =:= TLVType ->
		      handle_delete_array_tlv(TLV, T, Size);
		 (T, Acc) -> {T, Acc}
	      end,
    Iterator = fun(#lsp_frag{pseudonode = N, level = L,
			     tlvs = TLVs, size = OriginalSize} = F)
		     when N =:= Node, L =:= Level ->
		       case lists:mapfoldl(Deleter, {false, OriginalSize}, TLVs) of
			   {NewTLVs, {true, NewSize}} ->
			       isis_system:schedule_lsp_refresh(),
			       F#lsp_frag{updated = true,
					  size = NewSize,
					  tlvs = NewTLVs};
			   _ -> F
		       end;
		  (F) -> F
	       end,
    lists:map(Iterator, Frags).

handle_delete_array_tlv(#isis_tlv_is_reachability{is_reachability = Deleted},
			#isis_tlv_is_reachability{is_reachability = Existing} = Original,
			Size) ->
    NewD = lists:nth(1, Deleted),
    DeletedN = NewD#isis_tlv_is_reachability_detail.neighbor,
    Results = lists:filter(fun(#isis_tlv_is_reachability_detail{neighbor = N})
				 when N =:= DeletedN ->
				   false;
			      (_) -> true
			   end,
			   Existing),
    case length(Results) =:= length(Existing) of
	true -> {Original, {false, Size}};
	_ -> NewTLV = Original#isis_tlv_is_reachability{is_reachability = Results},
	     SizeDiff = tlv_size(Original) - tlv_size(NewTLV),
	     {NewTLV, {true, Size - SizeDiff}}
    end;
handle_delete_array_tlv(#isis_tlv_extended_reachability{reachability = Deleted},
			#isis_tlv_extended_reachability{reachability = Existing} = Original,
			Size) ->
    NewD = lists:nth(1, Deleted),
    DeletedN = NewD#isis_tlv_extended_reachability_detail.neighbor,
    Results = lists:filter(fun(#isis_tlv_extended_reachability_detail{neighbor = N})
				 when N =:= DeletedN ->
				   false;
			      (_) -> true
			   end,
			   Existing),
    case length(Results) =:= length(Existing) of
	true -> {Original, {false, Size}};
	_ -> NewTLV = Original#isis_tlv_extended_reachability{reachability = Results},
	     SizeDiff = tlv_size(Original) - tlv_size(NewTLV),
	     {NewTLV, {true, Size - SizeDiff}}
    end;
handle_delete_array_tlv(#isis_tlv_extended_ip_reachability{reachability = Deleted},
			#isis_tlv_extended_ip_reachability{reachability = Existing} = Original,
			Size) ->
    NewD = lists:nth(1, Deleted),
    DeletedP = NewD#isis_tlv_extended_ip_reachability_detail.prefix,
    DeletedM = NewD#isis_tlv_extended_ip_reachability_detail.mask_len,
    Results = lists:filter(fun(#isis_tlv_extended_ip_reachability_detail{
				  prefix = P, mask_len = M})
				 when P =:= DeletedP, M =:= DeletedM ->
				   false;
			      (_) -> true
			   end,
			   Existing),
    case length(Results) =:= length(Existing) of
	true -> {Original, {false, Size}};
	_ -> NewTLV = Original#isis_tlv_extended_ip_reachability{reachability = Results},
	     SizeDiff = tlv_size(Original) - tlv_size(NewTLV),
	     {NewTLV, {true, Size - SizeDiff}}
    end;
handle_delete_array_tlv(#isis_tlv_ipv6_reachability{reachability = Deleted},
			#isis_tlv_ipv6_reachability{reachability = Existing} = Original,
			Size) ->
    NewD = lists:nth(1, Deleted),
    DeletedP = NewD#isis_tlv_ipv6_reachability_detail.prefix,
    DeletedM = NewD#isis_tlv_ipv6_reachability_detail.mask_len,
    DeletedSTLV = NewD#isis_tlv_ipv6_reachability_detail.sub_tlv,
    Results = lists:filter(fun(#isis_tlv_ipv6_reachability_detail{
				  prefix = P, mask_len = M, sub_tlv = ST})
				 when P =:= DeletedP, M =:= DeletedM, ST =:= DeletedSTLV ->
				   false;
			      (_) -> true
			   end,
			   Existing),
    case length(Results) =:= length(Existing) of
	true -> {Original, {false, Size}};
	_ -> NewTLV = Original#isis_tlv_ipv6_reachability{reachability = Results},
	     SizeDiff = tlv_size(Original) - tlv_size(NewTLV),
	     {NewTLV, {true, Size - SizeDiff}}
    end.

%%% ===================================================================
%%% Generic merge / split routine for 'tlv as a whole', for example
%%% hostname, ipv6 reachability (until we do sub-tlv merging)
%%% ===================================================================
-spec merge_whole_tlv(fun(), isis_tlv(), integer(), atom(), [lsp_frag()]) -> [lsp_frag()].
merge_whole_tlv(Matcher, TLV, Node, Level, Frags) ->
    F = fun(#lsp_frag{pseudonode = N, level = L} = Frag, {false, _})
	   when N =:= Node, L =:= Level ->
		merge_whole_tlv(Matcher, TLV, Frag);
	   (Frag, {Found, Replaced}) ->
		{Frag, {Found, Replaced}}
	end,
    case lists:mapfoldl(F, {false, false}, Frags) of
	{NewFrags, {true, true}} -> NewFrags;
	{_, {_, _}} -> add_whole_tlv(TLV, Node, Level, Frags)
    end.

-spec merge_whole_tlv(fun(), isis_tlv(), lsp_frag()) -> lsp_frag().
merge_whole_tlv(Matcher, TLV, #lsp_frag{tlvs = TLVs, size = Size,
			       sequence = Seqno} = Frag) ->
    NewTLVs = lists:filter(Matcher, TLVs),
    %% If we didn't find a matching TLV type, no-op, otherwise we see
    %% if there's now room to fit the TLV into this fragment.
    case length(NewTLVs) =:= length(TLVs) of
	true -> {Frag, {false, false}};
	_ -> TLVB = encode_tlv(TLV),
	     TLVSize = binary_list_size(TLVB),
	     case (Size + TLVSize) < 1492 of
		 true -> {Frag#lsp_frag{tlvs = NewTLVs ++ [TLV],
					size = Size + TLVSize,
					sequence = Seqno + 1,
					updated = true},
			  {true, true}};
		 false -> {Frag, {true, false}}
	     end
    end.

%%% ===================================================================
%%% Add an entry to an array TLV. Find any existing TLV and see if we
%%% have space to add this array entry.
%%% ===================================================================
handle_add_array_tlv(#isis_tlv_is_reachability{is_reachability = Existing} = ET,
		     #isis_tlv_is_reachability{is_reachability = New},
		     Size)
  when length(New) =:= 1 ->
    NewD = lists:nth(1, New),
    ExistingSize = tlv_size(ET),
    NewList = Existing ++ [NewD],
    NewSize = tlv_size(ET#isis_tlv_is_reachability{is_reachability = NewList}),
    case (Size - ExistingSize + NewSize) =< 1492 of
	false -> {ET, {Size - ExistingSize + NewSize, false}};
	true -> {ET#isis_tlv_is_reachability{is_reachability = NewList},
		 {Size, true}}
    end;
handle_add_array_tlv(#isis_tlv_extended_reachability{reachability = Existing} = ET,
		     #isis_tlv_extended_reachability{reachability = New},
		     Size)
  when length(New) =:= 1 ->
    NewD = lists:nth(1, New),
    ExistingSize = tlv_size(ET),
    NewList = Existing ++ [NewD],
    NewSize = tlv_size(ET#isis_tlv_extended_reachability{reachability = NewList}),
    case (Size - ExistingSize + NewSize) =< 1492 of
	false -> {ET, {Size - ExistingSize + NewSize, false}};
	true -> {ET#isis_tlv_extended_reachability{reachability = NewList},
		 {Size, true}}
    end;
handle_add_array_tlv(#isis_tlv_extended_ip_reachability{reachability = Existing} = ET,
		     #isis_tlv_extended_ip_reachability{reachability = New},
		     Size)
  when length(New) =:= 1 ->
    NewD = lists:nth(1, New),
    ExistingSize = tlv_size(ET),
    NewList = Existing ++ [NewD],
    NewSize = tlv_size(ET#isis_tlv_extended_ip_reachability{reachability = NewList}),
    case (Size - ExistingSize + NewSize) =< 1492 of
	false -> {ET, {Size - ExistingSize + NewSize, false}};
	true -> {ET#isis_tlv_extended_ip_reachability{reachability = NewList},
		 {Size, true}}
    end;
handle_add_array_tlv(#isis_tlv_ipv6_reachability{reachability = Existing} = ET,
		     #isis_tlv_ipv6_reachability{reachability = New},
		     Size)
  when length(New) =:= 1 ->
    NewD = lists:nth(1, New),
    ExistingSize = tlv_size(ET),
    NewList = Existing ++ [NewD],
    NewSize = tlv_size(ET#isis_tlv_ipv6_reachability{reachability = NewList}),
    case (Size - ExistingSize + NewSize) =< 1492 of
	false -> {ET, {Size - ExistingSize + NewSize, false}};
	true -> 
	    isis_logger:debug("Adding new TLV ~p to existing set ~p", [New, Existing]),
	    {ET#isis_tlv_ipv6_reachability{reachability = NewList},
		 {Size, true}}
    end;
handle_add_array_tlv(ET, _, Size) ->
    {ET, {Size, false}}.
	    
add_array_tlv(TLV, Node, Level, Frags) ->
    TLVType = element(1, TLV),
    TestAddTLVs =
	fun(T, {Size, Added}) when element(1, T) =:= TLVType ->
		%% Found a matching TLV, see if we can add
		TLen = binary_list_size(encode_tlv(T)),
		R = handle_add_array_tlv(T, TLV, Size),
		R;
	   (T, Acc) ->
		{T, Acc}
	end,
    IterateFrags =
	fun(#lsp_frag{pseudonode = PN, level = L,
		      tlvs = TLVs, size = Size} = Frag, Acc)
	      when Acc =:= false, PN =:= Node, L =:= Level ->
		{NewTLVs, {NewSize, Added}} = 
		    lists:mapfoldl(TestAddTLVs, {Size, false}, TLVs),
		NewFrag = case Added of
			      true ->
				  isis_logger:debug("Scheduling refresh of TLV fragment PN ~p Frag ~p",
						    [PN, Frag#lsp_frag.fragment]),
				  isis_system:schedule_lsp_refresh(),
				  Frag#lsp_frag{tlvs = NewTLVs,
						size = NewSize,
						updated = true};
			      _ -> Frag
			  end,
		{NewFrag, Added};
	   (F, Acc) ->
		{F, Acc}
	end,
    case lists:mapfoldl(IterateFrags, false, Frags) of
	{_, false} -> add_whole_tlv(TLV, Node, Level, Frags);
	{NewFrags, true} -> NewFrags
    end.
    

%%% ===================================================================
%%% Merge an array tlv (eg. extended_ip_reachability,
%%% ip_internal_reachability).  For this we find every TLV of that
%%% type, then we walk the array to find any matching entry. If we
%%% find it, we update and refresh that LSP. If we don't, we continue
%%% until we've run out of TLVs. Then we start again, and we see if we
%%% can add to the first TLV, etc...
%%% ===================================================================
handle_merge_array_tlv(#isis_tlv_is_reachability{is_reachability = Existing} = ET,
		       #isis_tlv_is_reachability{is_reachability = New},
		       CurrentSize)
  when length(New) =:= 1 ->
    %% There is just one detail entry....
    NewD = lists:nth(1, New),
    ExistingSize = tlv_size(ET),
    NewNeighbor = NewD#isis_tlv_is_reachability_detail.neighbor,
    Updater = fun(#isis_tlv_is_reachability_detail{neighbor = N}, _Acc)
		    when N =:= NewNeighbor ->
		      {NewD, true};
		 (D, Acc) -> {D, Acc}
	end,
    Deleter = fun(#isis_tlv_extended_reachability_detail{neighbor = N}) ->
		      N =/= NewNeighbor
	      end,
    {NewTLV, Updated} = lists:mapfoldl(Updater, false, Existing),
    case Updated of
	true ->
	    FinalTLV = #isis_tlv_is_reachability{is_reachability = NewTLV},
	    NewSize = tlv_size(FinalTLV),
	    %% If the new detail entry pushes us over the LSP size, just
	    %% remove the old entry.
	    case (CurrentSize - ExistingSize + NewSize) >= 1492 of
		true ->
		    AfterDelete = lists:filter(Deleter, Existing),
		    DeletedTLV = #isis_tlv_is_reachability{is_reachability = AfterDelete},
		    DeletedSize = (CurrentSize - ExistingSize) + tlv_size(DeletedTLV),
		    {DeletedTLV,
		     {DeletedSize, false, length(AfterDelete) =/= length(Existing)}};
		_ ->
		    {FinalTLV,
		     {CurrentSize - ExistingSize + NewSize, true, true}}
	    end;
	_ -> {ET, {CurrentSize, false, false}}
    end;
handle_merge_array_tlv(#isis_tlv_extended_reachability{reachability = Existing} = ET,
		       #isis_tlv_extended_reachability{reachability = New},
		       CurrentSize)
  when length(New) =:= 1 ->
    %% There is just one detail entry....
    NewD = lists:nth(1, New),
    ExistingSize = tlv_size(ET),
    NewNeighbor = NewD#isis_tlv_extended_reachability_detail.neighbor,
    Updater = fun(#isis_tlv_extended_reachability_detail{neighbor = N}, _Acc)
		    when N =:= NewNeighbor ->
		      {NewD, true};
		 (D, Acc) -> {D, Acc}
	end,
    Deleter = fun(#isis_tlv_extended_reachability_detail{neighbor = N}) ->
		      N =/= NewNeighbor
	      end,
    {NewTLV, Updated} = lists:mapfoldl(Updater, false, Existing),
    case Updated of
	true ->
	    FinalTLV = #isis_tlv_extended_reachability{reachability = NewTLV},
	    NewSize = tlv_size(FinalTLV),
	    %% If the new detail entry pushes us over the LSP size, just
	    %% remove the old entry.
	    case (CurrentSize - ExistingSize + NewSize) >= 1492 of
		true ->
		    AfterDelete = lists:filter(Deleter, Existing),
		    DeletedTLV = #isis_tlv_extended_reachability{reachability = AfterDelete},
		    DeletedSize = (CurrentSize - ExistingSize) + tlv_size(DeletedTLV),
		    {DeletedTLV,
		     {DeletedSize, false, length(AfterDelete) =/= length(Existing)}};
		_ ->
		    {FinalTLV,
		     {CurrentSize - ExistingSize + NewSize, true, true}}
	    end;
	_ -> {ET, {CurrentSize, false, false}}
    end;
handle_merge_array_tlv(#isis_tlv_extended_ip_reachability{reachability = Existing} = ET,
		       #isis_tlv_extended_ip_reachability{reachability = New},
		       CurrentSize)
  when length(New) =:= 1 ->
    %% There is just one detail entry....
    NewD = lists:nth(1, New),
    ExistingSize = tlv_size(ET),
    NewPrefix = NewD#isis_tlv_extended_ip_reachability_detail.prefix,
    NewMask = NewD#isis_tlv_extended_ip_reachability_detail.mask_len,
    Updater = fun(#isis_tlv_extended_ip_reachability_detail{prefix = P, mask_len = M}, _Acc)
		    when P =:= NewPrefix, M =:= NewMask ->
		      {NewD, true};
		 (D, Acc) -> {D, Acc}
	end,
    Deleter = fun(#isis_tlv_extended_ip_reachability_detail{prefix = P, mask_len = M}) ->
		      (P =/= NewPrefix) and (M =/= NewMask)
	      end,
    {NewTLV, Updated} = lists:mapfoldl(Updater, false, Existing),
    case Updated of
	true ->
	    FinalTLV = #isis_tlv_extended_ip_reachability{reachability = NewTLV},
	    NewSize = tlv_size(FinalTLV),
	    %% If the new detail entry pushes us over the LSP size, just
	    %% remove the old entry.
	    case (CurrentSize - ExistingSize + NewSize) >= 1492 of
		true ->
		    AfterDelete = lists:filter(Deleter, Existing),
		    DeletedTLV = #isis_tlv_extended_ip_reachability{reachability = AfterDelete},
		    DeletedSize = (CurrentSize - ExistingSize) + tlv_size(DeletedTLV),
		    {DeletedTLV,
		     {DeletedSize, false, length(AfterDelete) =/= length(Existing)}};
		_ ->
		    {FinalTLV,
		     {CurrentSize - ExistingSize + NewSize, true, true}}
	    end;
	_ -> {ET, {CurrentSize, false, false}}
    end;
handle_merge_array_tlv(#isis_tlv_ipv6_reachability{reachability = Existing} = ET,
		       #isis_tlv_ipv6_reachability{reachability = New},
		       CurrentSize)
  when length(New) =:= 1 ->
    %% There is just one detail entry....
    NewD = lists:nth(1, New),
    ExistingSize = tlv_size(ET),
    NewPrefix = NewD#isis_tlv_ipv6_reachability_detail.prefix,
    NewMask = NewD#isis_tlv_ipv6_reachability_detail.mask_len,
    NewSTLV = NewD#isis_tlv_ipv6_reachability_detail.sub_tlv,
    Updater = fun(#isis_tlv_ipv6_reachability_detail{prefix = P,
						     mask_len = M,
						     sub_tlv = ST}, _Acc)
		    when P =:= NewPrefix, M =:= NewMask, ST =:= NewSTLV ->
		      {NewD, true};
		 (D, Acc) -> {D, Acc}
	end,
    Deleter = fun(#isis_tlv_ipv6_reachability_detail{prefix = P, mask_len = M, sub_tlv = ST}) ->
		      (P =/= NewPrefix) and (M =/= NewMask) and (ST =/= NewSTLV)
	      end,
    {NewTLV, Updated} = lists:mapfoldl(Updater, false, Existing),
    case Updated of
	true ->
	    FinalTLV = #isis_tlv_ipv6_reachability{reachability = NewTLV},
	    NewSize = tlv_size(FinalTLV),
	    %% If the new detail entry pushes us over the LSP size, just
	    %% remove the old entry.
	    case (CurrentSize - ExistingSize + NewSize) >= 1492 of
		true ->
		    AfterDelete = lists:filter(Deleter, Existing),
		    DeletedTLV = #isis_tlv_ipv6_reachability{reachability = AfterDelete},
		    DeletedSize = (CurrentSize - ExistingSize) + tlv_size(DeletedTLV),
		    {DeletedTLV,
		     {DeletedSize, false, length(AfterDelete) =/= length(Existing)}};
		_ ->
		    isis_logger:debug("merge_array_tlv: {~p, {~p, ~p, ~p}}",
				      [FinalTLV, CurrentSize - ExistingSize + NewSize, true, true]),
		    {FinalTLV,
		     {CurrentSize - ExistingSize + NewSize, true, true}}
	    end;
	_ -> {ET, {CurrentSize, false, false}}
    end.

merge_array_tlv(TLV, Node, Level, Frags) ->
    TLVType = element(1, TLV),
    SearchTLVs =
	fun(T, {Size, Found, Replaced}) when element(1, T) =:= TLVType ->
		%% Found a matching TLV, see if we can replace the array...
		TLen = binary_list_size(encode_tlv(TLV)),
		R = handle_merge_array_tlv(T, TLV, Size),
		R;
	   (T, Acc) ->
		{T, Acc}
	end,
    SearchFrags =
	fun(#lsp_frag{pseudonode = PN, level = L,
		      tlvs = TLVs, size = Size} = Frag, Acc)
	      when Acc =:= false, PN =:= Node, L =:= Level ->
		{NewTLVs, {NewSize, Replaced, Updated}} = 
		    lists:mapfoldl(SearchTLVs, {Size, false, false}, TLVs),
		NewFrag = 
		    case Updated of
			true ->
			    isis_logger:debug("Scheduling refresh of TLV fragment PN ~p Frag ~p",
					      [PN, Frag#lsp_frag.fragment]),
			    isis_system:schedule_lsp_refresh(),
			    Frag#lsp_frag{tlvs = NewTLVs,
					  size = NewSize,
					  updated = true};
			_ -> Frag
		    end,
		{NewFrag, Replaced};
	   (F, Acc) ->
		{F, Acc}
	end,
    {NewFrags, Acc} = lists:mapfoldl(SearchFrags, false, Frags),
    case Acc of
	false -> add_array_tlv(TLV, Node, Level, Frags);
	_ -> NewFrags
    end.
			 
%%% ===================================================================
%%% Add a TLV to the first available fragment. Does not check the
%%% TLV exists anywhere else, we assume that has been done.
%%% ===================================================================
-spec add_whole_tlv(isis_tlv(), integer(), atom(), [lsp_frag()]) -> [lsp_frag()].
add_whole_tlv(TLV, Node, Level, Frags) ->
    TLVSize = tlv_size(TLV),
    Add = fun(#lsp_frag{pseudonode = PN, size = Size, level = L,
			tlvs = TLVs, sequence = Seqno} = Frag, Acc)
		when Acc =:= false, PN =:= Node, L =:= Level ->
		  case (Size + TLVSize) < 1492 of
		      true ->
			  isis_logger:debug("Scheduling refresh of TLV fragment PN ~p Frag ~p",
					    [PN, Frag#lsp_frag.fragment]),
			  isis_system:schedule_lsp_refresh(),
			      {Frag#lsp_frag{size = Size + TLVSize,
					     tlvs = TLVs ++ [TLV],
					     updated = true},
			       true};
		      _ -> {Frag, false}
		  end;
	     (Frag, Acc) -> {Frag, Acc}
	  end,
    
    case lists:mapfoldl(Add, false, Frags) of
	{NewFrags, true} -> NewFrags;
	{_, false} -> create_new_frag(TLV, Node, Level, Frags)
    end.

%%% ===================================================================
%%% Create a new frag for the given pseudonode
%%% ===================================================================
-spec create_new_frag(isis_tlv(), integer(), atom(), [lsp_frag()]) -> [lsp_frag()].
create_new_frag(TLV, Node, Level, Frags) ->
    F = fun(#lsp_frag{pseudonode = PN, level = L, fragment = F})
	   when PN =:= Node, Level =:= L ->
		{true, F};
	   (_) -> false
	end,
    %% uses sets to get the next fragment
    S1 = sets:from_list(lists:filtermap(F, Frags)),
    S2 = sets:from_list(lists:seq(0, 255)),
    L = sets:to_list(sets:subtract(S2, S1)),
    FragNo = lists:nth(1, lists:sort(L)),
    TLVSize = tlv_size(TLV),
    Frag = #lsp_frag{level = Level,
		     pseudonode = Node,
		     fragment = FragNo,
		     tlvs = [TLV],
		     size = ?ISIS_MIN_MSG_SIZE + TLVSize,
		     updated = true},
    Frags ++ [Frag].

%%%===================================================================
%%% PDU decoders
%%%===================================================================
-spec decode_lan_iih(binary(), integer()) -> {ok, isis_iih()} | error.
decode_lan_iih(<<_Res1:6, Circuit_Type:2, Source_ID:6/binary,
		 Holding_Time:16, PDU_Len:16, _Res2:1, Priority:7,
		 DIS:7/binary, TLV_Binary/binary>>, PDU_Len_Received) ->
    TrueTLVBin =
	case PDU_Len < PDU_Len_Received of
	    true -> Bytes = byte_size(TLV_Binary) - (PDU_Len_Received - PDU_Len),
		    <<TB:Bytes/binary, _/binary>> = TLV_Binary,
		    TB;
	    _ -> TLV_Binary
	end,
    case decode_tlvs(TrueTLVBin, tlv, fun decode_tlv/3, []) of
	error -> throw(decode_error);
	{ok, TLVS} ->
	    CT = isis_enum:to_atom(istype, Circuit_Type),
	    {ok, #isis_iih{circuit_type = CT,
			   source_id = Source_ID,
			   holding_time = Holding_Time,
			   priority = Priority,
			   dis = DIS,
			   tlv = TLVS}}
    end.

decode_p2p_iih(<<_Res1:6, Circuit_Type:2, SourceID:6/binary,
		 Holding_Time:16, PDU_Len:16, LocalCircuitID:8,
		 TLV_Binary/binary>>, PDU_Len_Received) ->
    TrueTLVBin =
	case PDU_Len < PDU_Len_Received of
	    true -> Bytes = byte_size(TLV_Binary) - (PDU_Len_Received - PDU_Len),
		    <<TB:Bytes/binary, _/binary>> = TLV_Binary,
		    TB;
	    _ -> TLV_Binary
	end,
    case decode_tlvs(TrueTLVBin, tlv, fun decode_tlv/3, []) of
	error -> throw(decode_error);
	{ok, TLVS} ->
	    CT = isis_enum:to_atom(istype, Circuit_Type),
	    {ok, #isis_p2p_iih{
		    circuit_type = CT,
		    source_id = SourceID,
		    holding_time = Holding_Time,
		    local_circuit_id = LocalCircuitID,
		    tlv = TLVS}}
    end.

-spec decode_common_lsp(binary(), integer()) -> {ok, isis_lsp()} | error.
decode_common_lsp(<<PDU_Len:16, Lifetime:16,
		    Sys_Id:6/binary, Pnode:8, Fragment:8,
		    Sequence_Number:32, Checksum:16,
		    Partition:1, _ATT_Bits:4,
		    Overload:1, Type:2,
		    TLV_Binary/binary>>, PDU_Len_Received) ->
    TrueTLVBin =
	case PDU_Len < PDU_Len_Received of
	    true -> Bytes = byte_size(TLV_Binary) - (PDU_Len_Received - PDU_Len),
		    <<TB:Bytes/binary, _/binary>> = TLV_Binary,
		    TB;
	    _ -> TLV_Binary
	end,
    case decode_tlvs(TrueTLVBin, tlv, fun decode_tlv/3, []) of
	error -> throw(decode_error);
	{ok, TLVS} ->
	    LSP_ID = <<Sys_Id:6/binary, Pnode:8, Fragment:8>>,
	    {ok, #isis_lsp{pdu_type = pdu_type_unset,
			   lsp_id = LSP_ID,
			   last_update = current_timestamp(),
			   remaining_lifetime = Lifetime,
			   sequence_number = Sequence_Number,
			   checksum = Checksum,
			   partition = isis_enum:to_atom(boolean, Partition),
			   overload = isis_enum:to_atom(boolean, Overload),
			   isis_type = isis_enum:to_atom(istype, Type),
			   tlv = TLVS}}
    end.


-spec decode_common_csnp(binary(), integer()) -> {ok, isis_csnp()} | error.
decode_common_csnp(<<PDU_Len:16, Source:7/binary, Start:8/binary,
		     End:8/binary, TLV_Binary/binary>>, PDU_Len_Received) ->
    TrueTLVBin =
	case PDU_Len < PDU_Len_Received of
	    true -> Bytes = byte_size(TLV_Binary) - (PDU_Len_Received - PDU_Len),
		    <<TB:Bytes/binary, _/binary>> = TLV_Binary,
		    TB;
	    _ -> TLV_Binary
	end,
    case decode_tlvs(TrueTLVBin, tlv, fun decode_tlv/3, []) of
	error -> throw(decode_error);
	{ok, TLVS} ->
	    {ok, #isis_csnp{source_id = Source,
			    start_lsp_id = Start,
			    end_lsp_id = End,
			    tlv = TLVS}}
    end.


-spec decode_common_psnp(binary(), integer()) -> {ok, isis_psnp()} | error.
decode_common_psnp(<<PDU_Len:16, Source:7/binary,
		     TLV_Binary/binary>>, PDU_Len_Received) ->
    TrueTLVBin =
	case PDU_Len < PDU_Len_Received of
	    true -> Bytes = byte_size(TLV_Binary) - (PDU_Len_Received - PDU_Len),
		    <<TB:Bytes/binary, _/binary>> = TLV_Binary,
		    TB;
	    _ -> TLV_Binary
	end,
    case decode_tlvs(TrueTLVBin, tlv, fun decode_tlv/3, []) of
	error -> throw(decode_error);
	{ok, TLVS} ->
	    {ok, #isis_psnp{source_id = Source,
			    tlv = TLVS}}
    end.

-spec decode_pdu(atom(), isis_header(), integer(), binary()) -> {ok, isis_lsp()} | error.
decode_pdu(Type, #isis_header{id_length = Len}, PDU_Len, Rest) when
      Len =:= 0, Type =:= level1_iih; Len =:= 0, Type =:= level2_iih;
      Len =:= 6, Type =:= level1_iih; Len =:= 6, Type =:= level2_iih ->
    case decode_lan_iih(Rest, PDU_Len) of
	error -> throw(decode_error);
	{ok, IIH} ->
	    {ok, IIH#isis_iih{pdu_type = Type}}
    end;
decode_pdu(Type, #isis_header{id_length = Len}, PDU_Len, Rest) when
      Len =:= 0, Type =:= p2p_iih;
      Len =:= 6, Type =:= p2p_iih ->
    case decode_p2p_iih(Rest, PDU_Len) of
	error -> throw(decode_error);
	{ok, IIH} ->
	    {ok, IIH#isis_p2p_iih{pdu_type = Type}}
    end;
decode_pdu(Type, _Header, _PDU_Len, _Rest) when
      Type == level1_iih; Type == level2_iih ->
    invalid_id_len;
decode_pdu(Type, _Header, PDU_Len, Rest) when
      Type == level1_lsp; Type == level2_lsp->
    case decode_common_lsp(Rest, PDU_Len) of
	error -> throw(decode_error);
	{ok, Lsp} ->
	    {ok, Lsp#isis_lsp{pdu_type = Type}}
    end;
decode_pdu(Type, _Header, PDU_Len, Rest) when
      Type == level1_csnp; Type == level2_csnp ->
    case decode_common_csnp(Rest, PDU_Len) of
	error -> throw(decode_error);
	{ok, CSNP} ->
	    {ok, CSNP#isis_csnp{pdu_type = Type}}
    end;
decode_pdu(Type, _Header, PDU_Len, Rest) when
      Type == level1_psnp; Type == level2_psnp ->
    case decode_common_psnp(Rest, PDU_Len) of
	error -> throw(decode_error);
	{ok, PSNP} ->
	    {ok, PSNP#isis_psnp{pdu_type = Type}}
    end.

%%%===================================================================
%%% PDU encoders
%%%===================================================================
isis_header(Type, Len, IDLen, Area) ->
    T = isis_enum:to_int(pdu, Type),
    <<16#83:8, Len:8, 1:8, IDLen:8, 0:3, T:5, 1:8, 0:8,
      Area:8>>.

-spec encode_iih(isis_iih(), isis_crypto()) -> {ok, list(), integer()} | error.
encode_iih(#isis_iih{pdu_type = Type,
		     circuit_type = Circuit_Type,
		     source_id = Source_Id,
		     holding_time = Holding_Time,
		     priority = Priority,
		     dis = DIS,
		     tlv = TLVs},
	   Crypto) ->
    Header = isis_header(Type, 27, 0, 0),
    CT = isis_enum:to_int(istype, Circuit_Type),
    IIH1 = <<0:6, CT:2, Source_Id:6/binary, Holding_Time:16>>,
    IIH2 = <<0:1, Priority:7, DIS:7/binary>>,
    TLV_Bs = encode_tlvs(TLVs, fun encode_tlv/1),
    %% Add 2 bytes of length
    Len = binary_list_size([Header, IIH1, IIH2, TLV_Bs]) + 2,
    Pdu = insert_required_sig([Header, IIH1, <<Len:16>>, IIH2, TLV_Bs], Crypto),
    {ok, Pdu, Len}.

-spec encode_p2p_iih(isis_p2p_iih(), isis_crypto()) -> {ok, list(), integer()} | error.
encode_p2p_iih(#isis_p2p_iih{pdu_type = Type,
			     circuit_type = Circuit_Type,
			     source_id = Source_Id,
			     holding_time = Holding_Time,
			     local_circuit_id = LCID,
			     tlv = TLVs},
	       Crypto) ->
    Header = isis_header(Type, 20, 0, 0),
    CT = isis_enum:to_int(istype, Circuit_Type),
    IIH1 = <<0:6, CT:2, Source_Id:6/binary, Holding_Time:16>>,
    IIH2 = <<LCID:8>>,
    TLV_Bs = encode_tlvs(TLVs, fun encode_tlv/1),
    %% Add 2 bytes of length
    Len = binary_list_size([Header, IIH1, IIH2, TLV_Bs]) + 2,
    Pdu = insert_required_sig([Header, IIH1, <<Len:16>>, IIH2, TLV_Bs], Crypto),
    {ok, Pdu, Len}.

-spec encode_lsp(isis_lsp(), isis_crypto()) -> {ok, list(), integer()} | error.
encode_lsp(#isis_lsp{version = _Version, pdu_type = Lsp_Type,
		     remaining_lifetime = Lifetime,
		     lsp_id = LSP_Id, id_length = ID_Len,
		     sequence_number = Sequence,
		     partition = Partition, overload = Overload,
		     isis_type = ISType, tlv = TLVs},
	   Crypto) ->
    Header = isis_header(Lsp_Type, 27, ID_Len, 0),
    Pb = isis_enum:to_int(boolean, Partition),
    Ob = isis_enum:to_int(boolean, Overload),
    Ib = isis_enum:to_int(istype, ISType),
    Lsp_Hdr1 =
	case Lifetime =< 0 of
	    true -> <<0:16>>;
	    _ -> <<Lifetime:16>>
	end,
    Lsp_Hdr2 = <<LSP_Id:8/binary, Sequence:32>>,
    %% Hard code ATT bits to zero, deprecated...
    Lsp_Hdr3 = <<Pb:1, 0:4, Ob:1, Ib:2>>,
    TLV_Bs = encode_tlvs(TLVs, fun encode_tlv/1),
    %% Add 2 bytes of len and 2 bytes of fletcher checksum, hence 4
    Len = binary_list_size([Header, Lsp_Hdr1, Lsp_Hdr2, Lsp_Hdr3, TLV_Bs]) + 4,
    {CSum1, CSum2} =
	case Lifetime =< 0 of
	    true -> {0, 0};
	    _ -> calculate_checksum([Lsp_Hdr2, <<0:16>>, Lsp_Hdr3, TLV_Bs], 12)
	end,
    PDU = [Header, <<Len:16>>, Lsp_Hdr1, Lsp_Hdr2,
	  <<CSum1:8, CSum2:8>>, Lsp_Hdr3, TLV_Bs],
    {ok, insert_required_sig(PDU, Crypto), Len}.

-spec encode_csnp(isis_csnp(), isis_crypto()) -> {ok, list(), integer()} | error.
encode_csnp(#isis_csnp{pdu_type = Type, source_id = Source_Id,
		       start_lsp_id = Start_LSP, end_lsp_id = End_LSP,
		       tlv = TLVs},
	    Crypto) ->
    Header = isis_header(Type, 33, 0, 0),
    CSNP = <<Source_Id:7/binary, Start_LSP:8/binary, End_LSP:8/binary>>,
    TLV_Bs = encode_tlvs(TLVs, fun encode_tlv/1),
    %% Add 2 bytes of len
    Len = binary_list_size([Header, CSNP, TLV_Bs]) + 2,
    {ok, insert_required_sig([Header, <<Len:16>>, CSNP, TLV_Bs], Crypto), Len}.

-spec encode_psnp(isis_psnp(), isis_crypto()) -> {ok, list(), integer()} | error.
encode_psnp(#isis_psnp{pdu_type = Type, source_id = Source_Id,
		       tlv = TLVs},
	   Crypto) ->
    Header = isis_header(Type, 17, 0, 0),
    PSNP = <<Source_Id:7/binary>>,
    TLV_Bs = encode_tlvs(TLVs, fun encode_tlv/1),
    %% Add 2 bytes of len
    Len = binary_list_size([Header, PSNP, TLV_Bs]) + 2,
    {ok, insert_required_sig([Header, <<Len:16>>, PSNP, TLV_Bs], Crypto), Len}.

%%%===================================================================
%%% Utility functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Check to see if we require an crypto sig computing and
%% inserting...
%% --------------------------------------------------------------------
hunt_for_sigmarker(Item, {CompleteList, Crypto}) 
  when is_list(Item) ->
    {insert_required_sig(CompleteList, Item, Crypto), {CompleteList, Crypto}};
hunt_for_sigmarker(Item, {CompleteList, Crypto})
  when is_binary(Item) ->
    {Item, {CompleteList, Crypto}};
hunt_for_sigmarker({md5_signature, [_TLV]}, {CompleteList, {md5, Key} = Crypto}) ->
    %% MD5 sig required, generate one...
    MD5sum = calculate_md5sum(CompleteList, Key),
    AuthType = isis_enum:to_int(authentication_type, md5),
    {encode_tlv(authentication, tlv, <<AuthType:8, MD5sum:16/binary>>),
     {CompleteList, Crypto}};
hunt_for_sigmarker({md5_signature, [TLV]}, {CompleteList, Crypto}) ->
    %% Found an md5sig marker, but we're not doing MD5???
    %% Do what we can...
    {TLV, {CompleteList, Crypto}};
hunt_for_sigmarker(A, B) ->
    isis_logger:debug("hunt_for_sigmarker called with ~p ~p", [A, B]),
    {A, B}.

%% If the crypto is 'none', there's no work to do here...
insert_required_sig(PduBinList, Crypto) ->
    insert_required_sig(PduBinList, PduBinList, Crypto).

insert_required_sig(CompleteList, SubList, Crypto) ->
    {NewPDUList, _} = 
	lists:mapfoldl(
	  fun hunt_for_sigmarker/2,
	  {CompleteList, Crypto}, SubList),
    NewPDUList.


calculate_md5sum(IoList, Key) ->
    Ctxt = crypto:hmac_init(md5, Key),
    NCtxt = calculate_md5sum_work(Ctxt, IoList),
    crypto:hmac_final(NCtxt).

calculate_md5sum_work(Ctxt, IoList) ->
    lists:foldl(
      fun(E, C) when is_list(E) ->
	      calculate_md5sum_work(C, E);
	 (E, C) when is_binary(E) ->
	      crypto:hmac_update(C, E);
	 ({md5_signature, [E]}, C) when is_binary(E) ->
	      crypto:hmac_update(C, E)
      end, Ctxt, IoList).

%%--------------------------------------------------------------------
%% @doc Converts a deeplist into a size, used rather than flattening
%% the list of lists of binarys that are used to build PDUs
%% Ignore list heads which are not binary, or {_, Binary}
%% {_, Binary} could be {md5_signature, Binary}
%% @end
%%--------------------------------------------------------------------
binary_list_size([H | T], Acc) when is_list(H) ->
    binary_list_size(T, binary_list_size(H, Acc));
binary_list_size([H | T], Acc) when is_binary(H) ->
    binary_list_size(T, Acc + byte_size(H));
%% Handle the messy case of {md5_signature, [<<tlv>>]}
binary_list_size([{_, H} | T], Acc) when is_list(H) ->
    binary_list_size(T, binary_list_size(H, Acc));
binary_list_size([_ | T], Acc) ->
    binary_list_size(T, Acc);
%binary_list_size(B, Acc) when is_binary(B)->
%    Acc + byte_size(B);
binary_list_size([], Acc) ->
    Acc.

binary_list_size(Binaries) ->
    binary_list_size(Binaries, 0).

%%--------------------------------------------------------------------
%% @doc Takes a list of binaries (deeplist style) and calculates the
%% fletcher checksum. If this has been called with the checksum in
%% place, the result should be {0,0} to show the checksum is valid.
%%
%% @end
%%--------------------------------------------------------------------
-spec fletcher_checksum(list(), {integer(), integer()}) -> {integer(), integer()}.
fletcher_checksum([H|T], {CSum1, CSum2}) ->
    CSum = lists:foldl(fun(A, {Sum1, Sum2}) ->
			       S1 = ((Sum1 + A) rem 255),
			       S2 = ((Sum2 + S1) rem 255),
			       {S1, S2}
		       end,
		       {CSum1, CSum2}, [X || <<X:8>> <= H]),
    fletcher_checksum(T, CSum);
fletcher_checksum([], {CSum1, CSum2}) ->
    {CSum1, CSum2}.

verify_checksum(V) ->
    fletcher_checksum(lists:flatten(V), {0, 0}) == {0, 0}.

%%--------------------------------------------------------------------
%% @doc Computes the checksum to be used in the packet. This requires
%% to now the offset where the checksum will be placed and needs to
%% know the length, so for now we flatten the deeplist (ugh).
%%
%% Its left to the caller to install the checksum, and assumes that
%% the current place for the checksum is already zero.
%%
%% @end
%%--------------------------------------------------------------------
-spec calculate_checksum(list(), integer()) -> {integer(), integer()}.
calculate_checksum(V, Offset) ->
    B = list_to_binary(V),
    {CSum1, CSum2} = fletcher_checksum([B], {0, 0}),
    X1 = ((byte_size(B) - Offset -1) * CSum1 - CSum2) rem 255,
    X = case X1 =< 0 of
	     true -> (X1 + 255);
	     false -> X1
	 end,
    Y1 = 510 - CSum1 - X,
    Y  = case Y1 >= 255 of
	     true -> Y1 - 255;
	     false -> Y1
	 end,
    {X, Y}.

%%--------------------------------------------------------------------
%% @doc
%% Jitter the timer according to the percent provided
%%
%% @end
%%--------------------------------------------------------------------
-spec jitter(integer(), integer()) -> integer().
jitter(Miliseconds, JitterPercent) ->
    round(Miliseconds * ((100-random:uniform(JitterPercent)) / 100)).

%%--------------------------------------------------------------------
%% @doc
%% Returns a timestamp in seconds that we can use to simply compare if
%% LSPs have expired.
%%
%% @end
%%--------------------------------------------------------------------
-spec current_timestamp() -> integer().
current_timestamp() ->
    {A, B, _} = os:timestamp(),
    ((A * 100000) + B).

%%--------------------------------------------------------------------
%% @doc
%% Remaining Lifetime = Lifetime - (Now - Last Update).
%%
%% @end
%%--------------------------------------------------------------------
-spec fixup_lifetime( isis_lsp()) -> isis_lsp().
fixup_lifetime(#isis_lsp{remaining_lifetime = L, last_update = U} = LSP) ->
    Remaining =
	case (L - (current_timestamp() - U)) < 0 of
	    true -> 0;
	    _ -> L - (current_timestamp() - U)
	end,
    LSP#isis_lsp{remaining_lifetime = Remaining}.

-spec filter_lifetime(isis_lsp()) -> boolean().
filter_lifetime(#isis_lsp{remaining_lifetime = L, last_update = U}) ->
    Remaining = L - (current_timestamp() - U),
    Remaining > 0.

%%--------------------------------------------------------------------
%% @doc Calculate the checksum for a given LSP record - used when we
%% are the ones creating the LSP
%% @end
%%--------------------------------------------------------------------
checksum(#isis_lsp{lsp_id = LSP_Id,
		   sequence_number = Sequence,
		   partition = Partition, overload = Overload,
		   isis_type = ISType, tlv = TLVs}) ->
    %% Header = isis_header(Lsp_Type, 27, 0, 0),
    Pb = isis_enum:to_int(boolean, Partition),
    Ob = isis_enum:to_int(boolean, Overload),
    Ib = isis_enum:to_int(istype, ISType),
    %% Lsp_Hdr1 = <<Lifetime:16>>,
    Lsp_Hdr2 = <<LSP_Id:8/binary, Sequence:32>>,
    %% Hard code ATT bits to zero, deprecated...
    Lsp_Hdr3 = <<Pb:1, 0:4, Ob:1, Ib:2>>,
    TLV_Bs = encode_tlvs(TLVs, fun encode_tlv/1),
    %% Len = binary_list_size([Header, Lsp_Hdr1, Lsp_Hdr2, Lsp_Hdr3, TLV_Bs]) + 4,
    {CSum1, CSum2} = calculate_checksum([Lsp_Hdr2, <<0:16>>, Lsp_Hdr3, TLV_Bs], 12),
    (CSum1 * 256) + CSum2.

%% Return the Size of a given TLV when encoded
tlv_size([H | T]) ->
    tlv_size(T) + tlv_size(H);
tlv_size([]) -> 0;
tlv_size(TLV) ->
    TLVB = encode_tlv(TLV),
    binary_list_size(TLVB).

%%--------------------------------------------------------------------
%% @doc Calculate the md5 checksum for a given PDU. USed when
%% verifying a PDU and when generating one.  @end
%% --------------------------------------------------------------------
md5sum(_PDU, none) ->
    error;
md5sum(PDU, {md5, Key}) ->
    {ok, PduBin, _Len} = encode(PDU, none),
    calculate_md5sum(PduBin, Key).

%%--------------------------------------------------------------------
%% @doc Return the authentication TLV for the given crypto type @end
%% --------------------------------------------------------------------
authentication_tlv(Crypto) ->
    case Crypto of
	undefined -> [];
	none -> [];
	{text, Key} ->
	    [#isis_tlv_authentication{
		type = text,
		signature = Key}];
	{md5, _Key} ->
	    [#isis_tlv_authentication{
		type = md5,
		%% Signature needs to be calculated later, so must be rewritten
		signature = <<0:(16*8)>>,
		do_not_rewrite = false}]
    end.

%% Used for self-generated LSPS. We want to generate the auth_tlv and
%% calculate the signature
authentication_tlv_with_sig(
  #isis_lsp{version = _Version, pdu_type = Lsp_Type,
	    lsp_id = LSP_Id, id_length = ID_Len,
	    sequence_number = Sequence,
	    partition = Partition, overload = Overload,
	    isis_type = ISType, tlv = TLVs},
  {md5, Key} = Crypto) ->
    AuthTLV = authentication_tlv(Crypto),
    Header = isis_header(Lsp_Type, 27, ID_Len, 0),
    Pb = isis_enum:to_int(boolean, Partition),
    Ob = isis_enum:to_int(boolean, Overload),
    Ib = isis_enum:to_int(istype, ISType),
    Lsp_Hdr1 = <<0:16>>,
    Lsp_Hdr2 = <<LSP_Id:8/binary, Sequence:32>>,
    %% Hard code ATT bits to zero, deprecated...
    Lsp_Hdr3 = <<Pb:1, 0:4, Ob:1, Ib:2>>,
    TLV_Bs = encode_tlvs(AuthTLV ++ TLVs, fun encode_tlv/1),
    Len = binary_list_size([Header, Lsp_Hdr1, Lsp_Hdr2, Lsp_Hdr3, TLV_Bs]) + 4,
    Sig = calculate_md5sum([Header, <<Len:16>>, Lsp_Hdr1, Lsp_Hdr2, <<0:16>>, Lsp_Hdr3, TLV_Bs], Key),
    [#isis_tlv_authentication{
     	type = md5,
     	signature = Sig}];
authentication_tlv_with_sig(_PDU, none) ->
    [].


%%%===================================================================
%%% Pretty Print a TLV
%%%===================================================================
pp_tlv(T) ->
    TLVName = 
	case hd(tuple_to_list(T)) of
	    isis_tlv_unknown ->
		lists:flatten(io_lib:format("TLV#~B", [T#isis_tlv_unknown.type]));
	    V ->
		lists:sublist(erlang:atom_to_list(V), 10, 100)
	end,
    {TLVName, do_pp_tlv(T)}.

do_pp_tlv(#isis_tlv_area_address{areas = As}) ->
    AF = fun(A) -> isis_cli:pp_binary(A, ".") end,
    AStr = lists:foldl(fun(A, Acc) -> Acc ++ " " ++ AF(A) end,
		       "", As),
    lists:flatten(io_lib:format("~s", [AStr]));
do_pp_tlv(#isis_tlv_is_reachability{is_reachability = R}) ->
    lists:map(fun(#isis_tlv_is_reachability_detail{neighbor = N, default = D}) ->
		      <<SID:6/binary, PN:8>> = N,
		      lists:flatten(io_lib:format("~s.~2.16.0B metric ~B",
						  [isis_system:lookup_name(SID), PN,
						   D#isis_metric_information.metric]))
	      end, R);
do_pp_tlv(#isis_tlv_dynamic_hostname{hostname = H}) ->
    lists:flatten(io_lib:format("~s", [H]));
do_pp_tlv(#isis_tlv_protocols_supported{protocols = Protocols}) ->
    PStr = lists:foldl(fun(P, Acc) -> Acc ++ erlang:atom_to_list(P) ++ " " end,
		       "", Protocols),
    lists:flatten(io_lib:format("~s", [PStr]));
do_pp_tlv(#isis_tlv_hardware_fingerprint{fingerprint = F}) ->
    lists:flatten(io_lib:format("~s", [isis_cli:pp_binary(F, ".")]));
do_pp_tlv(#isis_tlv_ipv6_interface_address{addresses = A}) ->
    lists:map(fun(B) -> isis_system:address_to_string(ipv6, B) end, A);
do_pp_tlv(#isis_tlv_ipv6_reachability{reachability = R}) ->
    lists:map(fun(#isis_tlv_ipv6_reachability_detail{prefix = P, mask_len = Mask, metric = Metric,
						     sub_tlv = S}) ->
		      IA = #isis_address{afi = ipv6, address = P, mask = Mask},
		      SubTLV = lists:foldl(fun(ST, Acc) ->
						   Acc ++ do_pp_subtlv_ipv6r(ST) ++ " "
					   end,
					   "", S),
		      lists:flatten(io_lib:format("~s/~B metric ~B (~s)",
						  [isis_system:address_to_string(IA),
						   Mask, Metric, SubTLV]))
	      end, R);
do_pp_tlv(#isis_tlv_extended_reachability{reachability = R}) ->
    lists:map(fun(#isis_tlv_extended_reachability_detail{neighbor = N, metric = M}) ->
		      <<SID:6/binary, PN:8>> = N,
		      lists:flatten(io_lib:format("~s.~2.16.0B metric ~B",
						  [isis_system:lookup_name(SID), PN,
						   M]))
	      end, R);
do_pp_tlv(#isis_tlv_extended_ip_reachability{reachability = R}) ->
    lists:map(fun(#isis_tlv_extended_ip_reachability_detail{prefix = P, mask_len = Mask, metric = Metric,
							    sub_tlv = S}) ->
		      lists:flatten(io_lib:format("~s/~B metric ~B ~p",
						  [isis_system:address_to_string(ipv4, P),
						   Mask, Metric, S]))
	     end, R);
do_pp_tlv(#isis_tlv_te_router_id{router_id = ID}) ->
    isis_system:address_to_string(ipv4, ID);
do_pp_tlv(#isis_tlv_geninfo{application_id = ID, application_ip_address = IP,
			    application_gunk = G}) ->
    lists:flatten(
      io_lib:format("App ID: ~B, App IP: ~s, Data: ~p",
		    [ID,
		     case IP of
			 undefined -> "undefined";
			 _ -> isis_system:address_to_string(IP)
		     end, G]));
do_pp_tlv(#isis_tlv_unknown{bytes = B}) ->
    lists:flatten(io_lib:format("~p", [B]));
do_pp_tlv(T) ->
    lists:flatten(io_lib:format("~p", [T])).

do_pp_subtlv_ipv6r(#isis_subtlv_srcdst{prefix_length = PL, prefix = P}) ->
    AI = #isis_address{afi = ipv6, address = P, mask = PL},
    lists:flatten(io_lib:format("from: ~s/~B", [isis_system:address_to_string(AI), PL]));
do_pp_subtlv_ipv6r(#isis_subtlv_unknown{type = T, value = V}) ->
    lists:flatten(io_lib:format("TLV ~B (~p)", [T, V])).

%%%===================================================================
%%% EUnit tests
%%%===================================================================
-spec isis_protocol_test() -> no_return().
isis_protocol_test() ->
    ?assertMatch(error, isis_protocol:decode(isis_debug:invalid_lsp())),
    DecodeDLSPResult = isis_protocol:decode(isis_debug:valid_lsp()),
    ?assertMatch({ok, _LSP}, DecodeDLSPResult),
    DecodedCSNPResult = isis_protocol:decode(isis_debug:valid_csnp()),
    ?assertMatch({ok, _CSNP}, DecodedCSNPResult),
    {ok, LSP} = DecodeDLSPResult,
    %% Expected to fail from here for now...
    {ok, EncodedLSP, _Len} = isis_protocol:encode(LSP, none),
    ELSP = list_to_binary(EncodedLSP),
    ?assertMatch(ELSP, isis_debug:valid_lsp()).
