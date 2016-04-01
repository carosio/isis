-module(cowboy_embed).
-export([start/0, run/0]).

start() ->
    {ok, spawn(?MODULE, run, [])}.

run() ->
    Webport = 8080,
    Dispatch = cowboy_router:compile([
        {'_', [{"/lspdb", lsp_feed,   []},
               {"/spf",   spf_feed,   []},
               {"/unify", unify_feed, []},
               {"/unify_hostinfo", unify_hostinfo_feed, []},
               {"/database.html", web_database, []},
               {"/state", web_state, []},
               {"/state-netconf.xml", web_state_netconf, []},
               {"/title", web_title, []},
               {"/", cowboy_static, {priv_file, isis, "web/index.html"}},
               {"/[...]", cowboy_static, {priv_dir, isis, "web"}}]}
    ]),
    cowboy:start_http(cowboy_embed, 100, [{port, Webport}],
        [{env, [{dispatch,Dispatch}]}]
    ).
