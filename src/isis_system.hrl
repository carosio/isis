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
%%% Created :  10 March 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------

-record (isis_address, {
	   afi :: atom(),
	   address :: integer(),
	   mask :: integer(),
	   metric :: integer()
	  }).
-type isis_address() :: #isis_address{}.

-record (isis_prefix, {
	   afi :: atom(),
	   address :: integer(),
	   mask_length :: integer()
	  }).
-type isis_prefix() :: #isis_prefix{}.

-record (isis_route_key, {
	   prefix :: isis_prefix(),
	   source = undefined :: isis_prefix() | undefined
	  }).
-type isis_route_key() :: #isis_route_key{}.

-record (isis_route, {
	   route :: isis_route_key(),
	   nexthops = [] :: [integer()],
	   ifindexes = [] :: [integer()],
	   metric :: integer()
	  }).
-type isis_route() :: #isis_route{}.

-record (isis_interface, {
	   name :: string(),
	   mac :: binary(),
	   metric = 10 :: integer(),
	   flags :: integer(),
	   enabled = false :: atom(),
	   status :: integer(),
	   bandwidth :: integer(),
	   pid :: pid(),
	   addresses = [] :: [isis_address()],
	   ifindex :: integer(),
	   mtu :: integer(),
	   mtu6 :: integer()
	  }).
-type isis_interface() :: #isis_interface{}.

-record (isis_name, {
	   system_id :: binary(),
	   name :: string()
	  }).
-type isis_name() :: #isis_name{}.
