%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% @end
%%% Created :  2 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_enum).
-author('Rick Payne <rickp@rossfell.co.uk>').

-enum({isis_pdu, [{pdu_type_unset, 0},   %% Make typer happy
		  {level1_iih, 15},
		  {level2_iih, 16},
		  {p2p_iih, 17},
		  {level1_lsp, 18},
		  {level2_lsp, 20},
		  {level1_csnp, 24},
		  {level2_csnp, 25},
		  {level1_psnp, 26},
		  {level2_psnp, 27}]}).

-enum({isis_tlv, [{unknown, 0},
		  {area_address, 1},
		  {is_reachability, 2},
		  {is_neighbors, 6},
		  {padding, 8},
		  {lsp_entry, 9},
		  {authentication, 10},
		  {checksum, 12},
		  {extended_reachability, 22},
		  {is_alias, 24},
		  {ip_internal_reachability, 128},
		  {protocols_supported, 129},
		  {ip_external_reachability, 130},
		  {idrp_information, 131},
		  {ip_interface_address, 132},
		  {te_router_id, 134},
		  {extended_ip_reachability, 135},
		  {dynamic_hostname, 137},
		  {slrg, 138},
		  {restart_signaling, 211},
		  {mt_is_reachability, 222},
		  {mt_supported, 229},
		  {ipv6_interface_address, 232},
		  {mt_ipv6_reachability, 237},
		  {p2p_adjacency_state, 240},
		  {iih_sequence_number, 241},
		  {vendor_proprietary, 250}
		 ]}).

-enum({isis_subtlv_is_reachability,
       [{admin_group, 3},
	{link_local_ri, 4},
	{link_remote_ri, 5},
	{ipv4_interface_address, 6},
	{ipv4_neighbor_address, 8},
	{max_link_bandwidth, 9},
	{reservable_link_bandwidth, 10},
	{unreserved_bandwidth, 11},
	{traffic_engineering_metric, 18},
	{link_protection_type, 20},
	{interface_switching_capability, 21}
	]}).

-enum({isis_subtlv_ip_reachability,
       [{admin_tag_32bit, 1},
	{admin_tag_64bit, 2},
	{management_prefix_colour, 117}
	]}).

