%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%% Define the TLVs used for our zclient implementation.
%%%
%%% This file is part of AutoISIS.
%%%
%%% License:
%%% AutoISIS can be used (at your option) under the following GPL or under
%%% a commercial license
%%% 
%%% Choice 1: GPL License
%%% AutoISIS is free software; you can redistribute it and/or modify it
%%% under the terms of the GNU General Public License as published by the
%%% Free Software Foundation; either version 2, or (at your option) any
%%% later version.
%%% 
%%% AutoISIS is distributed in the hope that it will be useful, but
%%% WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See 
%%% the GNU General Public License for more details.
%%% 
%%% You should have received a copy of the GNU General Public License
%%% along with GNU Zebra; see the file COPYING.  If not, write to the Free
%%% Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
%%% 02111-1307, USA.
%%% 
%%% Choice 2: Commercial License Usage
%%% Licensees holding a valid commercial AutoISIS may use this file in 
%%% accordance with the commercial license agreement provided with the 
%%% Software or, alternatively, in accordance with the terms contained in 
%%% a written agreement between you and the Copyright Holder.  For
%%% licensing terms and conditions please contact us at 
%%% licensing@netdef.org
%%%
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

-enum({safi, [{unicast, 1},
	      {multicast, 2},
	      {reserved, 3},
	      {mpls_vpn, 4}]}).

-enum({nexthop, [{ifindex, 1},
		 {ifname, 2},
		 {ipv4, 3},
		 {ipv4_ifindex, 4},
		 {ipv4_ifname, 5},
		 {ipv6, 6},
		 {ipv6_ifindex, 7},
		 {ipv6_ifname, 8},
		 {blackhole, 9}]}).
