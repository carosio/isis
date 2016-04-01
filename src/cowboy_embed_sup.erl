-module(cowboy_embed_sup).
-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    CowboyEmbed = {cowboy_embed, {cowboy_embed, start, []},
           permanent, 2000, worker, [cowboy_embed]},
    {ok, {{one_for_all, 0, 1}, [CowboyEmbed]}}.
