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
-export([decode/1]).
-export_type([isis_message/0]).

%%%===================================================================
%%% API
%%%===================================================================

-spec decode(binary()) -> {ok, isis_message()} | error.
decode(Binary) when byte_size(Binary) >= ?ISIS_MIN_MSG_SIZE ->
    <<16#83:8, Len:8, Version:8, ID_Len:8,
    _Res1:3, PDU_Type:5, PDU_Version:8, _Res2:8,
    Max_Areas:8, Rest/binary>> = Binary,
    Type =
	try isis_enum:to_atom(isis_pdu, PDU_Type) of
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
    decode_pdu(Type, Header, Rest);
decode(_Binary) -> error.

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------

%%%===================================================================
%%% Internal functions
%%%===================================================================
-spec decode_tlv(atom(), integer(), binary()) -> isis_tlv().
decode_tlv(dynamic_hostname, _Type, Value) ->
    #isis_tlv_dynamic_hostname{hostname = binary:bin_to_list(Value)};
decode_tlv(ip_interface_address, _Type, Value) ->
    Addresses = [X || <<X:32>> <= Value],
    #isis_tlv_ip_interface_address{addresses = Addresses};
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
	try isis_enum:to_atom(isis_tlv, Type) of
	    Atom -> Atom
	catch
	    bad_enum -> unknown
	end,
    TLV = decode_tlv(TLV_Type, Type, Value),
    decode_tlvs(Rest, [TLV | TLVs]).

-spec decode_common_lsp(isis_header(), binary()) -> {ok, isis_lsp()} | error.
decode_common_lsp(Header, Rest) ->
    IDSize = 
	case Header#isis_header.id_length of
	    0 -> 8;
	    _ -> Header#isis_header.id_length + 2
	end,
    <<_PDU_Len:16, Lifetime:16, LSP_ID:IDSize/binary,
      Sequence_Number:32, _Checksum:16, _Flags:8,
      TLV_Binary/binary>> = Rest,
    {ok, TLVS} = decode_tlvs(TLV_Binary, []),
    {ok, #isis_lsp{version = Header#isis_header.version,
		   pdu_type = pdu_type_unset,
		   remaining_lifetime = Lifetime,
		   lsp_id = LSP_ID,
		   sequence_number = Sequence_Number,
		   tlv = TLVS}}.

-spec decode_pdu(atom(), isis_header(), binary()) -> {ok, isis_lsp()} | error.
decode_pdu(level2_lsp, Header, Rest) ->
    {ok, Lsp} = decode_common_lsp(Header, Rest),
    {ok, Lsp#isis_lsp{pdu_type = level2_lsp}};
decode_pdu(level1_lsp, Header, Rest) ->
    {ok, Lsp} = decode_common_lsp(Header, Rest),
    {ok, Lsp#isis_lsp{pdu_type = level1_lsp}};
decode_pdu(pdu_type_unset, _Header, _Rest) -> error;
decode_pdu(_, _, _) -> error.

%%%===================================================================
%%% EUnit tests
%%%===================================================================
isis_protocol_test() ->
    ?assertMatch(error, isis_protocol:decode(?TEST_INVALID_LSP)),
    ?assertMatch({ok, _LSP}, isis_protocol:decode(?TEST_VALID_LSP)).
