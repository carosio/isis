-module(ybed_sup).
-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    YBed = {ybed, {ybed, start, []},
	    permanent, 2000, worker, [ybed]},
    {ok, {{one_for_all, 0, 1}, [YBed]}}.
