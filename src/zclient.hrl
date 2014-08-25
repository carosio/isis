%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
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
%%% Created :  2 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------

-define (ZEBRA_HEADER_MARKER, 255).
-define (ZEBRA_HEADER_SIZE, 6).
-define (ZSERV_VERSION, 2).

-define (ZEBRA_AFI_IPV4, 2).
-define (ZEBRA_AFI_IPV6, 10).

%%%===================================================================
%%% Messages
%%%===================================================================
-record (zclient_header, {
	   command :: atom(),
	   length :: integer()
	  }).
-type zclient_header() :: #zclient_header{}.

%%%===================================================================
%%% Structures built from those messages
%%%===================================================================
-record (zclient_prefix, {
	   afi :: atom(),
	   address :: integer(),
	   mask_length :: integer(),
	   flags :: integer()
	  }).
-type zclient_prefix() :: #zclient_prefix{}.

-record (zclient_route_key, {
	   prefix :: zclient_prefix,
	   source = undefined :: zclient_prefix() | undefined
	  }).
-type zclient_route_key() :: #zclient_route_key{}.

-record (zclient_route, {
	   route :: zclient_route_key(),
	   nexthops = [] :: [integer()],
	   ifindexes = [] :: [integer()],
	   metric :: integer()
	  }).
-type zclient_route() :: #zclient_route{}.
	   
-record (zclient_interface, {
	   name :: string(),
	   ifindex :: integer(),
	   status :: integer(),
	   flags :: integer(),
	   metric :: integer(),
	   mtu :: integer(),
	   mtu6 :: integer(),
	   bandwidth :: integer(),
	   mac :: binary(),
	   addresses = [] :: [zclient_prefix()]
	  }).
-type zclient_interface() :: #zclient_interface{}.

