%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% @end
%%% Created :  2 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_protocol).
-author("Rick Payne <rickp@rossfell.co.uk>").

-include("isis_protocol.hrl").
-include_lib("eunit/include/eunit.hrl").

%% API
-export([decode/1, encode/2, decode_tlvs/2, encode_tlv/1, encode_lsp/2]).
-export_type([isis_pdu/0]).

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
decode(Binary) when byte_size(Binary) >= ?ISIS_MIN_MSG_SIZE ->
    <<16#83:8, Len:8, Version:8, ID_Len:8,
    _Res1:3, PDU_Type:5, PDU_Version:8, _Res2:8,
    Max_Areas:8, Rest/binary>> = Binary,
    Type =
	try isis_enum:to_atom(pdu, PDU_Type) of
	    Atom -> Atom
	catch
	    bad_enum -> pdu_type_unset
	end,
    Header = #isis_header{
		header_length = Len,
		version = Version,
		id_length = ID_Len,
		pdu_type = Type,
		pdu_version = PDU_Version,
		maximum_areas = Max_Areas},
    decode_pdu(Type, Header, byte_size(Binary), Rest);
decode(_Binary) -> error.

%%--------------------------------------------------------------------
%% @doc encode a set of IS-IS terms into a PDU
%% @end
%%--------------------------------------------------------------------
-spec encode(atom(), isis_pdu()) -> {ok, binary()} | error.
encode(pdu_type_unset, _Message) ->
    error;
encode(level1_iih, _Message) ->
    error;
encode(level2_iih, _Message) ->
    error;
encode(p2p_iih, _Message) ->
    error;
encode(level1_lsp, #isis_lsp{} = LSP) ->
    encode_lsp(level1_lsp, LSP);
encode(level2_lsp, #isis_lsp{} = LSP) ->
    encode_lsp(level2_lsp, LSP);
encode(level1_csnp, _Message) ->
    error;
encode(level2_csnp, _Message) ->
    error;
encode(level1_psnp, _Message) ->
    error;
encode(level2_psnp, _Message) ->
    error;
encode(_, _) ->
    error.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%%===================================================================
%%% TLV and subTLV decoders
%%%===================================================================
-spec decode_subtlv_eir_value(binary(), atom()) -> {ok, isis_subtlv_eir()} | error.
decode_subtlv_eir_value(<<Value:32>>, admin_tag_32bit) ->
    {ok, #isis_subtlv_eir_admintag32{tag = Value}};
decode_subtlv_eir_value(<<Value:64>>, admin_tag_64bit) ->
    {ok, #isis_subtlv_eir_admintag64{tag = Value}};
decode_subtlv_eir_value(_, _) -> error.

-spec decode_subtlv_eir(binary(), [isis_subtlv_eir()]) -> [isis_subtlv_eir()] | error.
decode_subtlv_eir(<<Type:8, Length:8, Value:Length/binary, Rest/binary>>, SubTLVs) ->
    TypeA =
	try isis_enum:to_atom(subtlv_eir, Type) of
	    Atom -> Atom
	catch
	    bad_enum -> error
	end,
    case decode_subtlv_eir_value(Value, TypeA) of
	{ok, SubTLV} ->
	    decode_subtlv_eir(Rest, [SubTLV | SubTLVs]);
	_ -> error
    end;
decode_subtlv_eir(<<>>, SubTLVs) ->
    lists:reverse(SubTLVs);
decode_subtlv_eir(_, _) -> error.

-spec decode_tlv_area_address(binary(), [binary()]) -> [binary()] | error.
decode_tlv_area_address(<<>>, Areas) ->
    lists:reverse(Areas);
decode_tlv_area_address(<<Len:8, Area:Len/binary, Rest/binary>>, Areas) ->
    decode_tlv_area_address(Rest, [Area | Areas]);
decode_tlv_area_address(_, _) ->
    error.

-spec decode_tlv_lsp_entry(binary(), [isis_tlv_lsp_entry_detail()]) ->
				  [isis_tlv_lsp_entry_detail()] | error.
decode_tlv_lsp_entry(<<>>, LSPs) ->
    lists:reverse(LSPs);
decode_tlv_lsp_entry(<<Lifetime:16, LSP_Id:8/binary,
		       Sequence:32, Checksum:16, Rest/binary>>, LSPs) ->
    decode_tlv_lsp_entry(Rest, [#isis_tlv_lsp_entry_detail{
				   lifetime = Lifetime,
				   lsp_id = LSP_Id,
				   sequence = Sequence,
				   checksum = Checksum}
				| LSPs]);
decode_tlv_lsp_entry(_, _) ->
    error.

-spec decode_isis_metric_information(binary(), atom())
			       -> isis_metric_information().
decode_isis_metric_information(<<0:1, B7:1, Metric:6>>, default) ->
    #isis_metric_information{metric_supported = true,
			     metric_type = isis_enum:to_atom(metric_type, B7),
			     metric = Metric};
decode_isis_metric_information(<<B8:1, B7:1, Metric:6>>, Type) when
      Type /= default ->
    Supported = 
	case B8 of
	    0 -> false;
	    1 -> true
	end,
    #isis_metric_information{metric_supported = Supported,
			     metric_type = isis_enum:to_atom(metric_type, B7),
			     metric = Metric};
decode_isis_metric_information(_, default) -> error.

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
    lists:reverse(Values);
decode_tlv_ip_internal_reachability(_, _) -> error.

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
		<<SubTLV_Len:8, SubTLVb:SubTLV_Len/binary, Rest3/binary>> = Rest,
		{decode_subtlv_eir(SubTLVb, []), Rest3}
	end,
    UpA = isis_enum:to_atom(boolean, Up),
    EIR = #isis_tlv_extended_ip_reachability_detail{
	     prefix = Prefix,
	     mask_len = Mask_Len,
	     metric = Metric,
	     up = UpA,
	     sub_tlv = SubTLV},
    decode_tlv_extended_ip_reachability(Rest4, [EIR | Values]);
decode_tlv_extended_ip_reachability(<<>>, Values) ->
    lists:reverse(Values);
decode_tlv_extended_ip_reachability(_, _) -> error.


%%--------------------------------------------------------------------
%% @doc Convert a binary TLV into a record of the appropriate type,
%% or an 'unknown tlv' which can be re-encoded later
%% @end
%%--------------------------------------------------------------------
-spec decode_tlv(atom(), integer(), binary()) -> isis_tlv().
decode_tlv(area_address, _Type, Value) ->
    Areas = decode_tlv_area_address(Value, []),
    #isis_tlv_area_address{areas = Areas};
decode_tlv(padding, _Type, Value) ->
    #isis_tlv_padding{size = byte_size(Value)};
decode_tlv(lsp_entry, _Type, Value) ->
    LSPs = decode_tlv_lsp_entry(Value, []),
    #isis_tlv_lsp_entry{lsps = LSPs};
decode_tlv(dynamic_hostname, _Type, Value) ->
    #isis_tlv_dynamic_hostname{hostname = binary:bin_to_list(Value)};
decode_tlv(ip_internal_reachability, _Type, Value) ->
    Reachability = decode_tlv_ip_internal_reachability(Value, []),
    #isis_tlv_ip_internal_reachability{ip_reachability = Reachability};
decode_tlv(extended_ip_reachability, _Type, Value) ->
    EIR = decode_tlv_extended_ip_reachability(Value, []),
    #isis_tlv_extended_ip_reachability{reachability = EIR};
decode_tlv(ip_interface_address, _Type, Value) ->
    Addresses = [X || <<X:32>> <= Value],
    #isis_tlv_ip_interface_address{addresses = Addresses};
decode_tlv(protocols_supported, _Value, Value) ->
    Protocols = [isis_enum:to_atom(protocols, X)
		 || X <- binary:bin_to_list(Value)],
    #isis_tlv_protocols_supported{protocols = Protocols};
decode_tlv(unknown, Type, Value) ->
    #isis_tlv_unknown{type = Type, bytes = Value};
decode_tlv(_, Type, Value) ->
    decode_tlv(unknown, Type, Value).

-spec decode_tlvs(binary(), [isis_tlv()]) -> {ok, [isis_tlv()]} | error.
decode_tlvs(<<>>, TLVs) ->
    {ok, lists:reverse(TLVs)};
decode_tlvs(<<Type:8, Length:8, Value:Length/binary, Rest/binary>>,
	    TLVs) ->
    TLV_Type = 
	try isis_enum:to_atom(tlv, Type) of
	    Atom -> Atom
	catch
	    bad_enum -> unknown
	end,
    TLV = decode_tlv(TLV_Type, Type, Value),
    decode_tlvs(Rest, [TLV | TLVs]);
decode_tlvs(_, _) -> error.


%%%===================================================================
%%% TLV and subTLV encoders
%%%===================================================================
-spec encode_subtlv_eir_detail(isis_subtlv_eir()) -> binary().
encode_subtlv_eir_detail(#isis_subtlv_eir_admintag32{tag = Tag}) ->
    Type = isis_enum:to_int(subtlv_eir, admin_tag_32bit),
    <<Type:8, 4:8, Tag:32>>;
encode_subtlv_eir_detail(#isis_subtlv_eir_admintag64{tag = Tag}) ->
    Type = isis_enum:to_int(subtlv_eir, admin_tag_64bit),
    <<Type:8, 8:8, Tag:64>>.

-spec encode_subtlv_eir([isis_subtlv_eir()]) -> binary().
encode_subtlv_eir(SubTLVs) ->
    lists:foldr(
      fun(A, B) ->
	      Bs = encode_subtlv_eir_detail(A),
	      <<B/binary, Bs/binary>> end,
      <<>>, SubTLVs).
			
-spec encode_tlv_area_address([binary()], binary()) -> binary().
encode_tlv_area_address([A | As], B) ->
    S = byte_size(A),
    encode_tlv_area_address(As, <<B/binary, S:8, A/binary>>);
encode_tlv_area_address([], B) ->
    B.

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

-spec encode_tlv_extended_ip_reachability(isis_tlv_extended_ip_reachability_detail()) -> binary().
encode_tlv_extended_ip_reachability(
  #isis_tlv_extended_ip_reachability_detail{
     prefix = Prefix, mask_len = Mask_Len,
     metric = Metric, up = UpA,
     sub_tlv = SubTLVs}) ->

    SubTLVb = encode_subtlv_eir(SubTLVs),
    Present = 
	case byte_size(SubTLVb) of
	    0 -> 0;
	    _ -> 1
	end,
    %%% Mask_Len -> whole bytes, then we shift to lineup
    PLenBytes = erlang:trunc((Mask_Len + 7) / 8),
    PLenBits = PLenBytes * 8,
    Calc_Prefix = Prefix bsr (32 - PLenBits),
    Up = isis_enum:to_int(boolean, UpA),
    <<Metric:32, Up:1, Present:1, Mask_Len:6,
      Calc_Prefix:PLenBits, SubTLVb/binary>>.

-spec encode_tlv(isis_tlv()) -> binary().
encode_tlv(#isis_tlv_area_address{areas = Areas}) ->
    encode_tlv(area_address, encode_tlv_area_address(Areas, <<>>));
encode_tlv(#isis_tlv_padding{size = Size}) ->
    encode_tlv(isis_tlv_padding, <<0:(Size * 8)>>);
encode_tlv(#isis_tlv_lsp_entry{lsps = LSPS}) ->
    LSPb = lists:foldr(
	     fun(#isis_tlv_lsp_entry_detail{lifetime = Lifetime,
					    lsp_id = LSP_Id,
					    sequence = Sequence,
					    checksum = Checksum},
		B) -> 
		     <<B/binary, Lifetime:16, LSP_Id:8/binary, Sequence:32, Checksum:16>> end,
	     <<>>, LSPS),
    encode_tlv(lsp_entry, LSPb);
encode_tlv(#isis_tlv_ip_internal_reachability{ip_reachability = IP_Reachability}) ->
    IP_Rb = lists:foldr(
	      fun(#isis_tlv_ip_internal_reachability_detail{ip_address = IP_Address,
							    subnet_mask = Subnet_Mask,
							    default = Default,
							    delay = Delay,
							    expense = Expense,
							    error = Error}, B)
		 -> DefaultB = encode_tlv_metric_info(default, Default),
		    DelayB = encode_tlv_metric_info(false, Delay),
		    ExpenseB = encode_tlv_metric_info(false, Expense),
		    ErrorB = encode_tlv_metric_info(false, Error),
		    <<B/binary, DefaultB/binary, DelayB/binary,
		      ExpenseB/binary, ErrorB/binary,
		      IP_Address:32, Subnet_Mask:32>>
	      end,
	      <<>>, IP_Reachability),
    encode_tlv(ip_internal_reachability, IP_Rb);
encode_tlv(#isis_tlv_dynamic_hostname{hostname = Hostname}) ->
    encode_tlv(dynamic_hostname, binary:list_to_bin(Hostname));
encode_tlv(#isis_tlv_ip_interface_address{addresses = Addresses}) ->
    As = lists:foldr(fun(A, B) -> <<A:32, B/binary>> end,
		     <<>>, Addresses),
    encode_tlv(ip_interface_address, As);
encode_tlv(#isis_tlv_extended_ip_reachability{reachability = EIR}) ->
    Bs = lists:foldr(
	   fun(A, B) -> Ab = encode_tlv_extended_ip_reachability(A),
			<<B/binary, Ab/binary>> end,
	   <<>>, EIR),
    encode_tlv(extended_ip_reachability, Bs);
encode_tlv(#isis_tlv_protocols_supported{protocols = Protocols}) ->
    Ps = lists:foldr(fun(A, B) -> At = isis_enum:to_int(protocols, A),
				  <<At:8, B/binary>> end,
		     <<>>, Protocols),
    encode_tlv(protocols_supported, Ps);
encode_tlv(#isis_tlv_unknown{type = Type, bytes = Bytes}) ->
    <<Type:8, Bytes/binary>>;
encode_tlv(_) ->
    <<>>.

-spec encode_tlv(atom(), binary()) -> binary().
encode_tlv(Type, Value) ->
    T = isis_enum:to_int(tlv, Type),
    S = byte_size(Value),
    <<T:8, S:8, Value/binary>>.

%%%===================================================================
%%% PDU decoders
%%%===================================================================
%%-spec decode_lan_iih(isis_header(), integer(), binary()) -> {ok, isis_iih()} | error.
-spec decode_lan_iih(binary(), integer()) -> {ok, isis_iih()} | error.
decode_lan_iih(<<_Res1:6, Circuit_Type:2, Source_ID:6/binary,
		 Holding_Time:16, PDU_Len:16, _Res2:1, Priority:7,
		 DIS:7/binary, TLV_Binary/binary>>, PDU_Len) ->
    case decode_tlvs(TLV_Binary, []) of
	error -> error;
	{ok, TLVS} ->
	    {ok, #isis_iih{circuit_type = Circuit_Type,
			   source_id = Source_ID,
			   holding_time = Holding_Time,
			   priority = Priority,
			   dis = DIS,
			   tlv = TLVS}}
    end;
decode_lan_iih(_, _) -> error.

-spec decode_common_lsp(binary(), integer()) -> {ok, isis_lsp()} | error.
decode_common_lsp(<<PDU_Len:16, Lifetime:16, LSP_ID:8/binary,
		    Sequence_Number:32, _Checksum:16, _Flags:8,
		    TLV_Binary/binary>>, PDU_Len) ->
    case decode_tlvs(TLV_Binary, []) of
	error -> error;
	{ok, TLVS} ->
	    {ok, #isis_lsp{pdu_type = pdu_type_unset,
			   remaining_lifetime = Lifetime,
			   lsp_id = LSP_ID,
			   sequence_number = Sequence_Number,
			   tlv = TLVS}}
    end;
decode_common_lsp(_, _) -> error.


-spec decode_common_csnp(binary(), integer()) -> {ok, isis_csnp()} | error.
decode_common_csnp(<<PDU_Len:16, Source:7/binary, Start:8/binary,
		     End:8/binary, TLV_Binary/binary>>, PDU_Len) ->
    case decode_tlvs(TLV_Binary, []) of
	error -> error;
	{ok, TLVS} ->
	    {ok, #isis_csnp{source_id = Source,
			    start_lsp_id = Start,
			    end_lsp_id = End,
			    tlv = TLVS}}
    end;
decode_common_csnp(_, _) -> error.


-spec decode_common_psnp(binary(), integer()) -> {ok, isis_psnp()} | error.
decode_common_psnp(<<PDU_Len:16, Source:7/binary,
		     TLV_Binary/binary>>, PDU_Len) ->
    case decode_tlvs(TLV_Binary, []) of
	error -> error;
	{ok, TLVS} ->
	    {ok, #isis_psnp{source_id = Source,
			    tlv = TLVS}}
    end;
decode_common_psnp(_, _) -> error.

-spec decode_pdu(atom(), isis_header(), integer(), binary()) -> {ok, isis_lsp()} | error.
decode_pdu(Type, _Header, PDU_Len, Rest) when
      Type == level1_iih; Type == level2_iih ->
    case decode_lan_iih(Rest, PDU_Len) of
	error -> error;
	{ok, IIH} ->
	    {ok, IIH#isis_iih{pdu_type = Type}}
    end;
decode_pdu(Type, _Header, PDU_Len, Rest) when
      Type == level1_lsp; Type == level2_lsp->
    case decode_common_lsp(Rest, PDU_Len) of
	error -> error;
	{ok, Lsp} ->
	    {ok, Lsp#isis_lsp{pdu_type = Type}}
    end;
decode_pdu(Type, _Header, PDU_Len, Rest) when
      Type == level1_csnp; Type == level2_csnp ->
    case decode_common_csnp(Rest, PDU_Len) of
	error -> error;
	{ok, CSNP} ->
	    {ok, CSNP#isis_csnp{pdu_type = Type}}
    end;
decode_pdu(Type, _Header, PDU_Len, Rest) when
      Type == level1_psnp; Type == level2_psnp ->
    case decode_common_psnp(Rest, PDU_Len) of
	error -> error;
	{ok, PSNP} ->
	    {ok, PSNP#isis_psnp{pdu_type = Type}}
    end;
decode_pdu(_, _, _, _) -> error.

%%%===================================================================
%%% PDU encoders
%%%===================================================================

encode_lsp(Lsp_Type,
	   #isis_lsp{version = Version, pdu_type = Lsp_Type,
		     remaining_lifetime = Lifetime,
		     lsp_id = LSP_Id, sequence_number = Sequence,
		     tlv = TLVs} = PDU) ->
    TLV_Bs =
	lists:foldr(fun (A, B) ->
			    Ab = encode_tlv(A), <<Ab/binary, B/binary>>
		    end,
		    <<>>, TLVs),
    {ok, TLV_Bs}.
				 

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
    {ok, EncodedLSP} = isis_protocol:encode(level2_lsp, LSP),
    ?assertMatch(EncodedLSP, isis_debug:valid_lsp()).
