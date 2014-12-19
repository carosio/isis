# Starting Hostinfo

By default, hostinfo is not automatically started. I can be started from the ISIS cli with

    application:start(hostinfo).

(and to stop use `application:stop(hostinfo).` command)

## Automatically start hostinfo with AutoISIS

To start hostinfo automatically at start of AutoISIS, apply the following patch to the AutoISIS code:

	diff --git a/src/isis_sup.erl b/src/isis_sup.erl
	index 5063d2b..2c5fd17 100644
	--- a/src/isis_sup.erl
	+++ b/src/isis_sup.erl
	@@ -123,6 +123,9 @@ init([]) ->
		%%             permanent, 1000, worker, []},
		Webserver = {ybed_sup, {ybed_sup, start_link, []},
					permanent, 10000, supervisor, []},
	+
	+    timer:apply_after(10000, application, start, [hostinfo]),
	+
		{ok, {SupFlags, [SPFSummary, RibChild, L1DB, L2DB, ISIS, ISISRib, ISISGenIn
					   , Webserver %% , Demo
					   ]}}.

# Monitor information from hostinfo

To monitor the local and the remote hostinfo, use the web URL:

    http://x.x.x.x:8080/hostinfo.yaws

or use the cli debug command:

    hostinfo:get_state().
        
# Adding new information to hostinfo

The hostinfo application is designed to be extendable. The current code populates it with hostname, architecture, free memory and DNS-SD (Service Discovery). These are just 
implemented as a proof of concept and as example on how to add information.

## How to add addtional information

In basic there are 3 steps:

1. create the new record type in `hostinfo/src/hostinfo.hrl`
2. add routines to `encode_tlv/decode_tlv/mergetype_tlv/pp_hostinfo_tlv in hostinfo/src/hostinfo.erl`
3. add some code to initialise it in `hostinfo/src/hostinfo.erl:get_hostinfo()`

# Example to add a static "test" field

### Create the new record type:

    diff --git a/hostinfo/src/hostinfo.hrl b/hostinfo/src/hostinfo.hrl
    index fdaf098..6fa9579 100644
    --- a/hostinfo/src/hostinfo.hrl
    +++ b/hostinfo/src/hostinfo.hrl
    @@ -39,6 +39,9 @@
     -record (hostinfo_processor, {
               processor :: nonempty_string()}).
     
    +-record (hostinfo_test, {
    +           test :: nonempty_string()}).
    +
     -record (hostinfo_memused, {
               memory_used :: integer()}).

### Add routines to encode/decode/merge and initialize

	diff --git a/hostinfo/src/hostinfo.erl b/hostinfo/src/hostinfo.erl
	index f1685af..e1d13a9 100644
	--- a/hostinfo/src/hostinfo.erl
	+++ b/hostinfo/src/hostinfo.erl
	@@ -215,7 +215,8 @@ get_hostinfo() ->
		 [
		  #hostinfo_hostname{hostname = Hostname},
		  #hostinfo_processor{processor = Processor},
	-     #hostinfo_memused{memory_used = MemUsed}
	+     #hostinfo_memused{memory_used = MemUsed},
	+     #hostinfo_test{test = "Dummy"}
		 ].
	 
	 set_initial_state() ->
	@@ -349,8 +350,9 @@ encode_tlv(#hostinfo_dnssd{service_name = N,
		 NL = byte_size(N),
		 TL = byte_size(T),
		 DL = byte_size(D),
	-    encode_tlv(4, <<NL:8, N/binary, TL:8, T/binary, DL:8, D/binary>>).
	-
	+    encode_tlv(4, <<NL:8, N/binary, TL:8, T/binary, DL:8, D/binary>>);
	+encode_tlv(#hostinfo_test{test = X}) ->
	+    encode_tlv(5, erlang:list_to_binary(X)).
	 encode_tlv(T, V) ->
		 S = byte_size(V),
		 <<T:8,S:8,V/binary>>.
	@@ -364,7 +366,9 @@ decode_tlv(3, <<M:64>>) ->
	 decode_tlv(4, <<NL:8, N:NL/binary, TL:8, T:TL/binary, DL:8, D:DL/binary>>) ->
		 #hostinfo_dnssd{service_name = N,
						service_type = T,
	-                   service_domain = D}.
	+                   service_domain = D};
	+decode_tlv(5, Value) ->
	+    #hostinfo_test{test = erlang:binary_to_list(Value)}.
 
	 %% 1 TLV per type in hostinfo, so we replace Though with the dns-sd
	 %% stuff, we must match exactly as we can have multiple of the same
	@@ -372,7 +376,8 @@ decode_tlv(4, <<NL:8, N:NL/binary, TL:8, T:TL/binary, DL:8, D:DL/binary>>) ->
	 mergetype_tlv(#hostinfo_hostname{}) -> replace;
	 mergetype_tlv(#hostinfo_processor{}) -> replace;
	 mergetype_tlv(#hostinfo_memused{}) -> replace;
	-mergetype_tlv(#hostinfo_dnssd{}) -> match.
	+mergetype_tlv(#hostinfo_dnssd{}) -> match;
	+mergetype_tlv(#hostinfo_test{}) -> replace.
 
 
	 pp_hostinfo_tlv(#hostinfo_hostname{hostname = H}) ->
	@@ -388,4 +393,7 @@ pp_hostinfo_tlv(#hostinfo_dnssd{service_name = N,
					 io_lib:format("~s ~s ~s",
								   [binary_to_list(N),
									binary_to_list(T),
	-                               binary_to_list(D)]))}.
	+                               binary_to_list(D)]))};
	+pp_hostinfo_tlv(#hostinfo_test{test = X}) ->
	+    {"Test", X}.
	+
	diff --git a/hostinfo/src/hostinfo.hrl b/hostinfo/src/hostinfo.hrl
	index fdaf098..6fa9579 100644
	--- a/hostinfo/src/hostinfo.hrl
	+++ b/hostinfo/src/hostinfo.hrl
	@@ -39,6 +39,9 @@
	 -record (hostinfo_processor, {
			   processor :: nonempty_string()}).
 
	+-record (hostinfo_test, {
	+           test :: nonempty_string()}).
	+
	 -record (hostinfo_memused, {
			   memory_used :: integer()}).

