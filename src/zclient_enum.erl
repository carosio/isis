%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%% Define the TLVs used for our zclient implementation.
%%% @end
%%% Created :  21 Feb 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(zclient_enum).
-author('Rick Payne <rickp@rossfell.co.uk>').

-enum({zclient_command, [{unknown, 0},
			 {interface_add, 1},
			 {interface_delete, 2},
			 {interface_address_add, 3}, 
			 {interface_address_delete, 4},
			 {interface_up, 5},
			 {interface_down, 6},
			 {ipv4_route_add, 7},
			 {ipv4_route_delete, 8},
			 {ipv6_route_add, 9},
			 {ipv6_route_delete, 10},
			 {redistribute_add, 11},
			 {redistribute_delete, 12},
			 {redistribute_default_add, 13},
			 {redistribute_default_delete, 14},
			 {ipv4_nexthop_lookup, 15},
			 {ipv6_nexthop_lookup, 16},
			 {ipv4_import_lookup, 17},
			 {ipv6_import_lookup, 18},
			 {interface_rename, 19},
			 {router_id_add, 20},
			 {router_id_delete, 21},
			 {router_id_update, 22},
			 {hello, 23}]}).

-enum({zebra_route, [{system, 0},
		     {kernel, 1},
		     {connect, 2},
		     {static, 3},
		     {rip, 4},
		     {ripng, 5},
		     {ospf, 6},
		     {ospf6, 7},
		     {isis, 8},
		     {bgp, 9},
		     {hsls, 10},
		     {olsr, 11},
		     {bable, 12}]}).

-enum({afi, [{ipv4, 2},
	     {ipv6, 10}]}).
