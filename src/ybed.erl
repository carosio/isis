-module(ybed).

-export([start/0, run/0]).

-include_lib("yaws/include/yaws.hrl").

start() ->
    {ok, spawn(?MODULE, run, [])}.

run() ->
    Id = "isis",
    GconfList = [{id, Id},
		 {log_wrap_size, 10000},
		 {logdir, "www_logs"}
		],
    Docroot = code:lib_dir(isis, html),
    Webport = 8080,
    Appmods = {appmods, [
			 {"/spf", spf_feed},
			 {"/lspdb", lsp_feed},
			 {"/unify", unify_feed}
			]},
    SconfList = [
		 [{servername, "isis"},
		  {port, Webport},
		  {listen, {0,0,0,0}},
		  {docroot, Docroot},
		  Appmods
		 ]],
    {ok, SCList, GC, Childspecs} =
	yaws_api:embedded_start_conf(Docroot, SconfList, GconfList, Id),
    [supervisor:start_child(ybed_sup, Ch) || Ch <- Childspecs],
    yaws_api:setconf(GC, SCList),
    {ok, self()}.
