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
-export([decode/1, encode/1, calculate_checksum/2,
	 package_tlvs/3,
	 current_timestamp/0, fixup_lifetime/1, filter_lifetime/1]).

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
-spec encode(isis_pdu()) -> {ok, list(), integer()} | error.
encode(#isis_iih{} = IIH) ->
    encode_iih(IIH);
encode(#isis_lsp{} = LSP) ->
    encode_lsp(LSP);
encode(#isis_csnp{} = CSNP) ->
    encode_csnp(CSNP);
encode(#isis_psnp{} = PSNP) ->
    encode_psnp(PSNP);
encode(_) ->
    error.

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

    

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%%===================================================================
%%% TLV and subTLV decoders
%%%===================================================================
-spec decode_subtlv_eir(atom(), integer(), binary()) -> isis_subtlv_eir() | error.
decode_subtlv_eir(admin_tag_32bit, _Type, <<Value:32>>) ->
    #isis_subtlv_eir_admintag32{tag = Value};
decode_subtlv_eir(admin_tag_64bit, _Type, <<Value:64>>) ->
    #isis_subtlv_eir_admintag64{tag = Value};
decode_subtlv_eir(_, _, _) -> error.

-spec decode_subtlv_eis(atom(), integer(), binary()) -> isis_subtlv_eis() | error.
decode_subtlv_eis(link_id, _Type, <<Local:32, Remote:32>>) ->
    #isis_subtlv_eis_link_id{local = Local, remote = Remote};
decode_subtlv_eis(ipv4_interface, _Type, <<IP:32>>) ->
    #isis_subtlv_eis_ipv4_interface{address = IP};
decode_subtlv_eis(_, Type, Value) ->
    #isis_subtlv_eis_unknown{type = Type, value = Value}.

-spec decode_tlv_area_address(binary(), [binary()]) -> [binary()] | error.
decode_tlv_area_address(<<>>, Areas) ->
    lists:reverse(Areas);
decode_tlv_area_address(<<Len:8, Area:Len/binary, Rest/binary>>, Areas) ->
    decode_tlv_area_address(Rest, [Area | Areas]);
decode_tlv_area_address(_, _) ->
    error.

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
    lists:reverse(Neighbors);
decode_tlv_is_reachability(_, _) -> error.

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
    Supported = isis_enum:to_atom(boolean, B8),
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
		{decode_tlvs(SubTLVb, subtlv_eir, fun decode_subtlv_eir/3, []), Rest3}
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
	_ -> error
    end;    
decode_tlv_extended_reachability(<<>>, Values) ->
    lists:reverse(Values);
decode_tlv_extended_reachability(_, _) -> error.



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
decode_tlv(ipv6_reachability, _Type, <<Metric:32, Up:1, X:1, _S:1,
				       _Res:5, PLen:8, Rest/binary>>) ->
    PLenBytes = erlang:trunc((PLen + 7) / 8),
    <<Prefix:PLenBytes/binary, SubTLV/binary>> = Rest,
    #isis_tlv_ipv6_reachability{metric = Metric,
				 up = isis_enum:to_atom(boolean, Up),
				 external = isis_enum:to_atom(boolean, X),
				 mask_len = PLen,
				 prefix = Prefix,
				 sub_tlv = SubTLV};
decode_tlv(protocols_supported, _Type, Value) ->
    Protocols = [isis_enum:to_atom(protocols, X) || <<X:8>> <= Value],
    #isis_tlv_protocols_supported{protocols = Protocols};
decode_tlv(te_router_id, _Type, <<Router_Id:32>>) ->
    #isis_tlv_te_router_id{router_id = Router_Id};
decode_tlv(restart, _Type,
	   <<_Res:5, Supress:1, Ack:1, Restart:1>>) ->
    #isis_tlv_restart{
       request = isis_enum:to_atom(boolean, Restart),
       acknowledge = isis_enum:to_atom(boolean, Ack),
       supress_adjacency = isis_enum:to_atom(boolean, Supress),
       remaining = -1,
       neighbor = <<>>};
decode_tlv(restart, _Type,
	   <<_Res:5, Supress:1, Ack:1, Restart:1, Remaining:16>>) ->
    #isis_tlv_restart{
       request = isis_enum:to_atom(boolean, Restart),
       acknowledge = isis_enum:to_atom(boolean, Ack),
       supress_adjacency = isis_enum:to_atom(boolean, Supress),
       remaining = Remaining,
       neighbor = <<>>};
decode_tlv(restart, _Type,
	   <<_Res:5, Supress:1, Ack:1, Restart:1, Remaining:16, Neighbor:6/binary>>) ->
    #isis_tlv_restart{
       request = isis_enum:to_atom(boolean, Restart),
       acknowledge = isis_enum:to_atom(boolean, Ack),
       supress_adjacency = isis_enum:to_atom(boolean, Supress),
       remaining = Remaining,
       neighbor = Neighbor};
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
    case TLVDecode(TLV_Type, Type, Value) of
	error -> error;
	TLV ->
	    decode_tlvs(Rest, Enum, TLVDecode, [TLV | TLVs])
    end;
decode_tlvs(_, _,_,_) -> error.


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

encode_subtlv_eis_detail(#isis_subtlv_eis_link_id{local = Local,
						  remote = Remote}) ->
    encode_tlv(link_id, subtlv_eis, <<Local:32, Remote:32>>);
encode_subtlv_eis_detail(#isis_subtlv_eis_ipv4_interface{address = Address}) ->
    encode_tlv(ipv4_interface, subtlv_eis, <<Address:32>>);
encode_subtlv_eis_detail(#isis_subtlv_eis_unknown{type = Type, value = Value}) ->
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
    Up = isis_enum:to_int(boolean, UpA),
    [<<Metric:32, Up:1, Present:1, Mask_Len:6,
      Calc_Prefix:PLenBits, SubTLV_LenB/binary>> | SubTLVB].

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
encode_tlv(#isis_tlv_is_neighbors{neighbors = Neighbors}) ->
    encode_tlv_list(is_neighbors, tlv, Neighbors);
encode_tlv(#isis_tlv_padding{size = Size}) ->
    encode_tlv(padding, tlv, <<0:(Size * 8)>>);
encode_tlv(#isis_tlv_lsp_entry{lsps = LSPS}) ->
    LSPb = lists:map(fun encode_tlv_lsp_entry/1, LSPS),
    encode_tlv_list(lsp_entry, tlv, LSPb);
encode_tlv(#isis_tlv_ip_internal_reachability{ip_reachability = IP_Reachability}) ->
    IP_Rb = lists:map(fun encode_tlv_ip_internal_reachability/1, IP_Reachability),
    encode_tlv_list(ip_internal_reachability, tlv, IP_Rb);
encode_tlv(#isis_tlv_dynamic_hostname{hostname = Hostname}) ->
    encode_tlv(dynamic_hostname, tlv, binary:list_to_bin(Hostname));
encode_tlv(#isis_tlv_ip_interface_address{addresses = Addresses}) ->
    As = lists:map(fun(A) -> <<A:32>> end, Addresses),
    encode_tlv_list(ip_interface_address, tlv, As);
encode_tlv(#isis_tlv_extended_ip_reachability{reachability = EIR}) ->
    Bs = lists:map(fun encode_tlv_extended_ip_reachability/1, EIR),
    encode_tlv_list(extended_ip_reachability, tlv, Bs);
encode_tlv(#isis_tlv_ipv6_interface_address{addresses = Addresses}) ->
    Bs = lists:map(fun(B) -> <<B:16/binary>> end, Addresses),
    encode_tlv_list(ipv6_interface_address, tlv, Bs);
encode_tlv(#isis_tlv_ipv6_reachability{metric = Metric, up = Up, external = External,
				       mask_len = Mask_Len, prefix = Prefix,
				       sub_tlv = Sub_TLV}) ->
    P = case byte_size(Sub_TLV) of
	    0 -> 0;
	    _ -> 1
	end,
    U = isis_enum:to_int(boolean, Up),
    E = isis_enum:to_int(boolean, External),
    PBytes = erlang:trunc((Mask_Len + 7) / 8),
    encode_tlv(ipv6_reachability, tlv,
	       <<Metric:32, U:1, E:1, P:1, 0:5,
		 Mask_Len:8, Prefix:PBytes/binary, Sub_TLV/binary>>);
encode_tlv(#isis_tlv_extended_reachability{reachability = EIS}) ->
    Bs = lists:map(fun encode_tlv_extended_reachability/1, EIS),
    encode_tlv_list(extended_reachability, tlv, Bs);
encode_tlv(#isis_tlv_protocols_supported{protocols = Protocols}) ->
    Ps = lists:map(fun(A) -> At = isis_enum:to_int(protocols, A),
			     <<At:8>> end, Protocols),
    encode_tlv_list(protocols_supported, tlv, Ps);
encode_tlv(#isis_tlv_te_router_id{router_id = Router_Id}) ->
    encode_tlv(te_router_id, tlv, <<Router_Id:32>>);
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
    [<<T:8, S:8>> | Values].

-spec encode_tlvs(list(), fun()) -> [binary()].
encode_tlvs(TLVs, Encoder) ->
    lists:map(Encoder, TLVs).

%%%===================================================================
%%% PDU decoders
%%%===================================================================
-spec decode_lan_iih(binary(), integer()) -> {ok, isis_iih()} | error.
decode_lan_iih(<<_Res1:6, Circuit_Type:2, Source_ID:6/binary,
		 Holding_Time:16, PDU_Len:16, _Res2:1, Priority:7,
		 DIS:7/binary, TLV_Binary/binary>>, PDU_Len) ->
    case decode_tlvs(TLV_Binary, tlv, fun decode_tlv/3, []) of
	error -> error;
	{ok, TLVS} ->
	    CT = isis_enum:to_atom(istype, Circuit_Type),
	    {ok, #isis_iih{circuit_type = CT,
			   source_id = Source_ID,
			   holding_time = Holding_Time,
			   priority = Priority,
			   dis = DIS,
			   tlv = TLVS}}
    end;
decode_lan_iih(_, _) -> error.

-spec decode_common_lsp(binary(), integer()) -> {ok, isis_lsp()} | error.
decode_common_lsp(<<PDU_Len:16, Lifetime:16,
		    Sys_Id:6/binary, Pnode:8, Fragment:8,
		    Sequence_Number:32, Checksum:16,
		    Partition:1, _ATT_Bits:4,
		    Overload:1, Type:2,
		    TLV_Binary/binary>>, PDU_Len_Received) ->
    case decode_tlvs(TLV_Binary, tlv, fun decode_tlv/3, []) of
	error -> error;
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
    end;
decode_common_lsp(_, _) -> error.


-spec decode_common_csnp(binary(), integer()) -> {ok, isis_csnp()} | error.
decode_common_csnp(<<PDU_Len:16, Source:7/binary, Start:8/binary,
		     End:8/binary, TLV_Binary/binary>>, PDU_Len) ->
    case decode_tlvs(TLV_Binary, tlv, fun decode_tlv/3, []) of
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
    case decode_tlvs(TLV_Binary, tlv, fun decode_tlv/3, []) of
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
isis_header(Type, Len, Area) ->
    T = isis_enum:to_int(pdu, Type),
    <<16#83:8, Len:8, 1:8, 0:8, 0:3, T:5, 1:8, 0:8,
      Area:8>>.

-spec encode_iih(isis_iih()) -> {ok, list(), integer()} | error.
encode_iih(#isis_iih{pdu_type = Type,
		     circuit_type = Circuit_Type,
		     source_id = Source_Id,
		     holding_time = Holding_Time,
		     priority = Priority,
		     dis = DIS,
		     tlv = TLVs}) ->
    Header = isis_header(Type, 27, 0),
    CT = isis_enum:to_int(istype, Circuit_Type),
    IIH1 = <<0:6, CT:2, Source_Id:6/binary, Holding_Time:16>>,
    IIH2 = <<0:1, Priority:7, DIS:7/binary>>,
    TLV_Bs = encode_tlvs(TLVs, fun encode_tlv/1),
    Len = binary_list_size([Header, IIH1, IIH2, TLV_Bs]) + 2,
    Pdu = [Header, IIH1, <<Len:16>>, IIH2, TLV_Bs],
    {ok, Pdu, Len}.

-spec encode_lsp(isis_lsp()) -> {ok, list(), integer()} | error.
encode_lsp(#isis_lsp{version = _Version, pdu_type = Lsp_Type,
		     remaining_lifetime = Lifetime,
		     lsp_id = LSP_Id,
		     sequence_number = Sequence,
		     partition = Partition, overload = Overload,
		     isis_type = ISType, tlv = TLVs}) ->
    Header = isis_header(Lsp_Type, 27, 0),
    Pb = isis_enum:to_int(boolean, Partition),
    Ob = isis_enum:to_int(boolean, Overload),
    Ib = isis_enum:to_int(istype, ISType),
    Lsp_Hdr1 = <<Lifetime:16>>,
    Lsp_Hdr2 = <<LSP_Id:8/binary, Sequence:32>>,
    %% Hard code ATT bits to zero, deprecated...
    Lsp_Hdr3 = <<Pb:1, 0:4, Ob:1, Ib:2>>,
    TLV_Bs = encode_tlvs(TLVs, fun encode_tlv/1),
    Len = binary_list_size([Header, Lsp_Hdr1, Lsp_Hdr2, Lsp_Hdr3, TLV_Bs]) + 4,
    {CSum1, CSum2} = calculate_checksum([Lsp_Hdr2, <<0:16>>, Lsp_Hdr3, TLV_Bs], 12),
    PDU = [Header, <<Len:16>>, Lsp_Hdr1, Lsp_Hdr2,
	  <<CSum1:8, CSum2:8>>, Lsp_Hdr3, TLV_Bs],
    {ok, PDU, Len}.

-spec encode_csnp(isis_csnp()) -> {ok, list(), integer()} | error.
encode_csnp(#isis_csnp{pdu_type = Type, source_id = Source_Id,
		       start_lsp_id = Start_LSP, end_lsp_id = End_LSP,
		       tlv = TLVs}) ->
    Header = isis_header(Type, 33, 0),
    CSNP = <<Source_Id:7/binary, Start_LSP:8/binary, End_LSP:8/binary>>,
    TLV_Bs = encode_tlvs(TLVs, fun encode_tlv/1),
    Len = binary_list_size([Header, CSNP, TLV_Bs]) + 2,
    {ok, [Header, <<Len:16>>, CSNP, TLV_Bs], Len}.

-spec encode_psnp(isis_psnp()) -> {ok, list(), integer()} | error.
encode_psnp(#isis_psnp{pdu_type = Type, source_id = Source_Id,
		       tlv = TLVs}) ->
    Header = isis_header(Type, 17, 0),
    PSNP = <<Source_Id:7/binary>>,
    TLV_Bs = encode_tlvs(TLVs, fun encode_tlv/1),
    Len = binary_list_size([Header, PSNP, TLV_Bs]) + 2,
    {ok, [Header, <<Len:16>>, PSNP, TLV_Bs], Len}.

%%%===================================================================
%%% Utility functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Converts a deeplist into a size, used rather than flattening
%% the list of lists of binarys that are used to build PDUs
%% @end
%%--------------------------------------------------------------------
binary_list_size([H | T], Acc) when is_list(H) ->
    binary_list_size(T, binary_list_size(H, Acc));
binary_list_size([H | T], Acc) when is_binary(H) ->
    binary_list_size(T, Acc + byte_size(H));
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
    Remaining = L - (current_timestamp() - U),
    LSP#isis_lsp{remaining_lifetime = Remaining}.

-spec filter_lifetime(isis_lsp()) -> boolean().
filter_lifetime(#isis_lsp{remaining_lifetime = L, last_update = U}) ->
    Remaining = L - (current_timestamp() - U),
    Remaining > 0.

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
    {ok, EncodedLSP, _Len} = isis_protocol:encode(LSP),
    ELSP = list_to_binary(EncodedLSP),
    ?assertMatch(ELSP, isis_debug:valid_lsp()).
