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
%%--------------------------------------------------------------------
%% @doc Convert a binary TLV into a record of the appropriate type,
%% or an 'unknown tlv' which can be re-encoded later
%% @end
%%--------------------------------------------------------------------
-spec decode_tlv(atom(), integer(), binary()) -> isis_tlv().
decode_tlv(area_address, _Type, Value) ->
    Areas = decode_tlv_area_address(Value, []),
    #isis_tlv_area_address{areas = Areas};
decode_tlv(lsp_entry, _Type, Value) ->
    LSPs = decode_tlv_lsp_entry(Value, []),
    #isis_tlv_lsp_entry{lsps = LSPs};
decode_tlv(dynamic_hostname, _Type, Value) ->
    #isis_tlv_dynamic_hostname{hostname = binary:bin_to_list(Value)};
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
    decode_tlvs(Rest, [TLV | TLVs]).

%%%===================================================================
%%% TLV and subTLV encoders
%%%===================================================================
-spec encode_tlv_area_address([binary()], binary()) -> binary().
encode_tlv_area_address([A | As], B) ->
    S = byte_size(A),
    encode_tlv_area_address(As, <<B/binary, S:8, A/binary>>);
encode_tlv_area_address([], B) ->
    B.

-spec encode_tlv(atom(), binary()) -> binary().
-spec encode_tlv(isis_tlv()) -> binary().
encode_tlv(#isis_tlv_area_address{areas = Areas}) ->
    encode_tlv(area_address, encode_tlv_area_address(Areas, <<>>));
encode_tlv(#isis_tlv_dynamic_hostname{hostname = Hostname}) ->
    encode_tlv(dynamic_hostname, binary:list_to_bin(Hostname));
encode_tlv(#isis_tlv_ip_interface_address{addresses = Addresses}) ->
    As = lists:foldr(fun(A, B) -> <<A:32, B/binary>> end,
		     <<>>, Addresses),
    encode_tlv(ip_interface_address, <<As/binary>>);
encode_tlv(#isis_tlv_protocols_supported{protocols = Protocols}) ->
    Ps = lists:foldr(fun(A, B) -> At = isis_enum:to_int(protocols, A),
				  <<At:8, B/binary>> end,
		     <<>>, Protocols),
    encode_tlv(protocols_supported, Ps);
encode_tlv(#isis_tlv_unknown{type = Type, bytes = Bytes}) ->
    <<Type:8, Bytes/binary>>;
encode_tlv(_) ->
    <<>>.
encode_tlv(Type, Value) ->
    T = isis_enum:to_int(tlv, Type),
    S = byte_size(Value),
    <<T:8, S:8, Value/binary>>.

%%%===================================================================
%%% PDU decoders
%%%===================================================================

-spec decode_common_lsp(isis_header(), integer(), binary()) -> {ok, isis_lsp()} | error.
decode_common_lsp(Header, PDU_Len, Rest) ->
    IDSize = 
	case Header#isis_header.id_length of
	    0 -> 8;
	    _ -> Header#isis_header.id_length + 2
	end,
    <<Packet_Len:16, Lifetime:16, LSP_ID:IDSize/binary,
      Sequence_Number:32, _Checksum:16, _Flags:8,
      TLV_Binary/binary>> = Rest,
    case Packet_Len =:= PDU_Len of
	false -> error;
	_ ->
	    {ok, TLVS} = decode_tlvs(TLV_Binary, []),
	    {ok, #isis_lsp{version = Header#isis_header.version,
			   pdu_type = pdu_type_unset,
			   remaining_lifetime = Lifetime,
			   lsp_id = LSP_ID,
			   sequence_number = Sequence_Number,
			   tlv = TLVS}}
    end.

-spec decode_common_csnp(isis_header(), integer(), binary()) -> {ok, isis_csnp()} | error.
decode_common_csnp(_Header, PDU_Len, Rest) ->
    <<Packet_Len:16, Source:7/binary, Start:8/binary, End:8/binary, TLV_Binary/binary>>
	= Rest,
    io:format("Len ~p ~p ~n", [Packet_Len, PDU_Len]),
    case Packet_Len =:= PDU_Len of
	false -> error;
	_ ->
	    {ok, TLVS} = decode_tlvs(TLV_Binary, []),
	    {ok, #isis_csnp{source_id = Source,
			    start_lsp_id = Start,
			    end_lsp_id = End,
			    tlv = TLVS}}
    end.

-spec decode_pdu(atom(), isis_header(), integer(), binary()) -> {ok, isis_lsp()} | error.
decode_pdu(level2_lsp, Header, PDU_Len, Rest) ->
    {ok, Lsp} = decode_common_lsp(Header, PDU_Len, Rest),
    {ok, Lsp#isis_lsp{pdu_type = level2_lsp}};
decode_pdu(level1_lsp, Header, PDU_Len, Rest) ->
    {ok, Lsp} = decode_common_lsp(Header, PDU_Len, Rest),
    {ok, Lsp#isis_lsp{pdu_type = level1_lsp}};
decode_pdu(level1_csnp, Header, PDU_Len, Rest) ->
    {ok, CSNP} = decode_common_csnp(Header, PDU_Len, Rest),
    {ok, CSNP#isis_csnp{pdu_type = level1_csnp}};
decode_pdu(level2_csnp, Header, PDU_Len, Rest) ->
    {ok, CSNP} = decode_common_csnp(Header, PDU_Len, Rest),
    {ok, CSNP#isis_csnp{pdu_type = level2_csnp}};
decode_pdu(pdu_type_unset, _Header, _PDU_Len, _Rest) -> error;
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
	lists:foldr(fun (A, B) -> Ab = encode_tlv(A), <<A/binary, B/binary>> end,
		    <<>>, TLVs),
    {ok, TLV_Bs}.
				 

%%%===================================================================
%%% EUnit tests
%%%===================================================================
-spec isis_protocol_test() -> no_return().
isis_protocol_test() ->
    ?assertMatch(error, isis_protocol:decode(?TEST_INVALID_LSP)),
    DecodeDLSPResult = isis_protocol:decode(?TEST_VALID_LSP),
    ?assertMatch({ok, _LSP}, DecodeDLSPResult),
    DecodedCSNPResult = isis_protocol:decode(?TEST_VALID_CSNP),
    ?assertMatch({ok, _CSNP}, DecodedCSNPResult),
    {ok, LSP} = DecodeDLSPResult,
    {ok, EncodedLSP} = isis_protocol:encode(level2_lsp, LSP),
    ?assertMatch(EncodedLSP, ?TEST_VALID_LSP).
