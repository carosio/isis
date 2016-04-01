/* NetworkGraph class */

function is_internal(link) {
	return (link.source.type == 'router' && link.target.type == 'port'
		|| link.source.type == 'port' && link.target.type == 'router');
}

function is_router(node) {
	return node.type == 'router';
}

function is_port(node) {
	return node.type == 'port';
}

function is_pseudo(node) {
	return node.type == 'pseudo';
}

function NetworkGraph(svg) {
	var ng = this;

	this.svg = svg;

	this.nodes = [];
	this.links = [];

	this.link = svg.append("g").selectAll('.link');
	this.pseudo = svg.append("g").selectAll('.pseudo');
	this.router = svg.append("g").selectAll('.router-group');
	this.port = svg.append("g").selectAll('.port');

	this.update_size();

	this.force = d3.layout.force()
		.nodes(this.nodes)
		.links(this.links)
		.linkDistance(function(d) { return is_internal(d) ? 3 : 80; })
		.linkStrength(function(d) { return is_internal(d) ? 3 : 0.2; })
		.size([this.width, this.height])
		.charge(function(d) { return is_router(d) ? -4000 : -50; })
		.on("tick", function() { ng.tick(); });

	d3.select(window)
		.on('resize', function() { ng.update_size(); });
}

NetworkGraph.prototype.update_size = function() {
	this.width = parseInt(this.svg.style('width'), 10);
	this.height = parseInt(this.svg.style('height'), 10);

	if (this.force !== undefined) {
		this.force.size([this.width,this.height])
			  .start();
	}
};

NetworkGraph.prototype.tick = function() {
	this.link.attr('x1', function(d) { return d.source.x; })
		 .attr('y1', function(d) { return d.source.y; })
		 .attr('x2', function(d) { return d.target.x; })
		 .attr('y2', function(d) { return d.target.y; });

	this.pseudo.attr('cx', function(d) { return d.x; })
		   .attr('cy', function(d) { return d.y; });

	this.router.attr('transform', function(d) {
		return 'translate(' + d.x + ',' + d.y + ')';
	});

	this.port.attr('x', function(d) { return d.x; })
		 .attr('y', function(d) { return d.y; });
};

NetworkGraph.prototype.update = function(nodes, links) {
	var ng = this;

	for (var i = this.nodes.length - 1; i >= 0; i--) {
		var old_node = this.nodes[i];
		var new_node = nodes[old_node.name];

		if (new_node === undefined) {
			this.nodes.splice(i,1);
		} else {
			for (key in new_node)
				old_node[key] = new_node[key];
			new_node.found = true;
		}
	}

	for (var i in nodes) {
		var node = nodes[i];
		if (node.found === true)
			continue;
		this.nodes.push(node);
	}

	for (var i = this.links.length - 1; i >= 0; i--) {
		var old_link = this.links[i];
		var new_link = links[old_link.source.name + '_' + old_link.target.name];

		if (new_link === undefined) {
			this.links.splice(i,1);
		} else {
			new_link.found = true;
		}
	}

	for (var i in links) {
		var link = links[i];
		if (link.found === true)
			continue;

		var source = undefined;
		var target = undefined;

		for (var j in this.nodes) {
			var node = this.nodes[j];

			if (node.name == link.source)
				source = node;
			if (node.name == link.target)
				target = node;

			if (source !== undefined && target !== undefined)
				break;
		}

		if (source === undefined || target === undefined) {
			console.log("Got strange link:");
			console.log(link);
			console.log("Source: ", source);
			console.log("Target: ", target);
			continue;
		}

		this.links.push({
			source: source,
			target: target
		});
	}

	/* Update links between router ports */
	this.link = this.link.data(
		this.force.links().filter(function(link) {
						return !is_internal(link);
					  }),
		function(link) {
			return link.source.name + '-' + link.target.name;
		}
	);
	this.link.enter()
		.append('line')
		.attr('class', 'link');
	this.link.exit()
		.remove();
	this.link.style('opacity', function(d) {
		if (d.source.reachable && d.target.reachable)
			return '1.0';
		else
			return '0.1';
	});

	/* Update pseudonodes */
	this.pseudo = this.pseudo.data(
		this.force.nodes().filter(function(node) {
						return is_pseudo(node);
					}),
		function(node) {
			return node.name;
		}
	);
	this.pseudo.enter()
		.append('circle')
		.attr('class', 'pseudo')
		.attr('r', '4px');
	this.pseudo.exit()
		.remove();
	this.pseudo.style('opacity', function(d) {
		return (d.reachable) ? '1.0' : '0.1';
	});

	/* Update routers */
	this.router = this.router.data(
		this.force.nodes().filter(function(node) {
						return is_router(node);
					}),
		function(node) {
			return node.name;
		}
	);
	var router_g = this.router.enter()
		.append('g')
		.attr('class', 'router-group')
		.call(this.force.drag);
	router_g.append('circle')
		.attr('class', 'router')
		.attr('r', '15px');
	router_g.append('text')
		.attr('class', 'router-label')
		.attr('dx', '20px')
		.attr('dy', '.35em');
	this.router.exit()
		.remove();
	this.router.selectAll('text')
		.text(function(d) { return d.label; });
	this.router.style('opacity', function(d) {
		return (d.reachable) ? '1.0' : '0.1';
	});

	/* Update ports */
	this.port = this.port.data(
		this.force.nodes().filter(function(node) {
						return is_port(node);
					}),
		function(node) {
			return node.name;
		}
	);
	this.port.enter()
		 .append('text');
	this.port.exit()
		 .remove();
	this.port.attr('class', 'port')
		 .attr('filter', 'url(#solid)')
		 .text(function(d) { return d.label; })
		 .call(this.force.drag);
	this.port.style('opacity', function(d) {
		return (d.reachable) ? '1.0' : '0.1';
	});

	this.force.start();
};

/* Visual class */
function Visual(svg) {
	var v = this;

	this.lspdb = {};
	this.ng = new NetworkGraph(svg);
	window.setTimeout(function() {
		v.connect();
	}, 1000);
}

Visual.prototype.connect = function() {
	var v = this;

	console.log("Trying to connect to backend...");
	this.ws = new WebSocket("ws://" + document.location.host + '/unify');
	this.ws.onmessage = function(evt) {
		v.on_message(evt);
	};
	this.ws.onclose = function() {
		v.ws.onclose = function(){};
		v.ws.onerror = function(){};
		try {
			v.ws.close();
		} finally {
			v.lspdb = {};
			window.setTimeout(function() {
				v.connect();
			}, 5000);
		}
	}
	this.ws.onerror = this.ws.onclose;
	this.ws.onopen = function() {
		console.log("Connected.");
		v.ws.send("start");
	};
};

Visual.prototype.on_message = function(evt) {
	var obj = JSON.parse(evt.data);

	if (obj.id.slice(-2) != '00')
		return; /* Ignore fragments for now */

	node = obj.id.slice(0,-3)
	if (obj.operation == 'own-id') {
		this.own_id = obj.id;
	} else if (obj.operation == 'add') {
		if (obj.info.links === undefined)
			obj.info.links = [];
		this.lspdb[node] = obj.info;
	} else {
		delete this.lspdb[node];
	}

	this.update_graph();
};

Visual.prototype.update_graph = function() {
	var node_dict = {};
	var edge_dict = {};

	var add_edge = function(a, b) {
		edge_dict[a + '_' + b] = {
			source: a,
			target: b
		};
	};

	for (node_id in this.lspdb) {
		var node_info = this.lspdb[node_id];
		var node = {};
		node_dict[node_id] = node;

		node.name = node_id;
		node.label = (node_info.hostname) ? node_info.hostname : node.name;

		if (node_id.slice(-2) != '00') {
			node.type = 'pseudo';
			continue;
		} else {
			node.type = 'router';
		}

		if (node_info.interfaces !== undefined) {
			for (ifnum in node_info.interfaces) {
				var ifname = node_info.interfaces[ifnum];
				var if_id = node_id + '_' + ifname;
				var if_node = {
					name: if_id,
					type: 'port',
					label: ifname
				};
				node_dict[if_id] = if_node;

				add_edge(node_id, if_id);
			}
		}
	}

	for (node_id in this.lspdb) {
		var node_info = this.lspdb[node_id];

		for (index in node_info.links) {
			var link = node_info.links[index];

			if (node_id < link.neighbor)
				continue;

			var neighbor_info = this.lspdb[link.neighbor];
			if (neighbor_info === undefined)
				continue;

			var neighbor_link = undefined;
			for (index2 in neighbor_info.links) {
				var neighbor_link_info = neighbor_info.links[index2];
				if (neighbor_link_info.neighbor != node_id)
					continue;
				neighbor_link = neighbor_link_info;
				break;
			}

			if (neighbor_link === undefined)
				continue; /* Link is not bidi, no edge added to viz */

			var source = node_id;
			if (link.port !== undefined && source.slice(-2) == '00')
				source += '_' + link.port;

			var target = link.neighbor;
			if (neighbor_link.port !== undefined && target.slice(-2) == '00')
				target += '_' + neighbor_link.port;

			add_edge(source, target);
		}
	}


	/* Filter out unreachable nodes */
	var nodes_to_keep = {};
	var own_node = node_dict[this.own_id];
	if (own_node !== undefined)
		nodes_to_keep[this.own_id] = own_node;

	var changed = true;
	while (changed) {
		changed = false;
		for (var edge_id in edge_dict) {
			var edge = edge_dict[edge_id];
			var source_in_keep = nodes_to_keep[edge.source];
			var target_in_keep = nodes_to_keep[edge.target];

			if (source_in_keep !== undefined
			    && target_in_keep === undefined
                            && node_dict[edge.target] !== undefined) {
				nodes_to_keep[edge.target] = node_dict[edge.target];
				changed = true;
			} else if (source_in_keep === undefined
				   && target_in_keep !== undefined
                                   && node_dict[edge.source] !== undefined) {
				nodes_to_keep[edge.source] = node_dict[edge.source];
				changed = true;
			}
		}
	}

	var edges_to_keep = {};
	for (var edge_id in edge_dict) {
		var edge = edge_dict[edge_id];
		if (nodes_to_keep[edge.source] !== undefined
		    && nodes_to_keep[edge.target] !== undefined)
			edges_to_keep[edge_id] = edge;
	}

	for (var node_id in node_dict) {
		var node = node_dict[node_id];

		node.reachable = (nodes_to_keep[node_id] !== undefined);
	}

	this.ng.update(node_dict, edge_dict);
};

/* InfoBox class */
function InfoBox(container) {
	var info = this;

	this.container = container;
	this.display = this.container.selectAll('.hostinfo-display');

	this.hostinfo = {};

	this.display_dict = {};
	this.display_info = [];

	window.setTimeout(function() {
		info.connect();
	}, 1000);
}

InfoBox.prototype.connect = function() {
	var info = this;

	console.log("Trying to connect to hostinfo backend...");
	this.ws = new WebSocket("ws://" + document.location.host +
			'/unify_hostinfo');
	this.ws.onmessage = function(evt) {
		info.on_message(evt);
	};
	this.ws.onclose = function() {
		info.ws.onclose = function(){};
		info.ws.onerror = function(){};
		try {
			info.ws.close();
		} finally {
			info.hostinfo = {};
			window.setTimeout(function() {
				info.connect();
			}, 5000);
		}
	}
	this.ws.onerror = this.ws.onclose;
	this.ws.onopen = function() {
		console.log("Connected to hostinfo backend.");
		info.ws.send("start");
	};
};

InfoBox.prototype.on_message = function(evt) {
	var obj = JSON.parse(evt.data);
	var command = obj.command;

	delete obj['command'];
	obj.hostid += '.00';

	if (command == 'add') {
		this.hostinfo[obj.hostid] = obj;
	} else {
		delete this.hostinfo[obj.hostid];
	}

	this.update_display_info();
	this.update_display();
};

InfoBox.prototype.update_display_info = function() {
	var update_tlvs = function(info, tlvs) {
		if (info.tlv_dict === undefined) {
			info.tlv_dict = {};
			info.tlvs = [];
		}

		for (var type in tlvs) {
			if (type == 'Hostname')
				continue;

			var value = tlvs[type];

			var tlv = info.tlv_dict[type];
			if (tlv === undefined) {
				tlv = {};
				info.tlv_dict[type] = tlv;
				info.tlvs.push(tlv);
			}
			tlv.type = type;
			tlv.value = value;
		}

		for (var i = info.tlvs.length - 1; i >= 0; i--) {
			var type = info.tlvs[i].type;

			if (tlvs[type] === undefined) {
				info.tlvs.splice(i,1);
				delete info.tlv_dict[type];
			}
		}
	};

	for (var hostid in this.hostinfo) {
		var orig_info = this.hostinfo[hostid];
		var new_info = this.display_dict[hostid];

		if (new_info === undefined) {
			new_info = {};
			this.display_dict[hostid] = new_info;
			this.display_info.push(new_info);
		}

		new_info.hostid = orig_info.hostid;
		new_info.host = orig_info.host;
		update_tlvs(new_info, orig_info.tlvs);
	}

	for (var i = this.display_info.length - 1; i >= 0; i--) {
		var hostid = this.display_info[i].hostid;

		if (this.hostinfo[hostid] === undefined) {
			this.display_info.splice(i,1);
			delete this.display_dict[hostid];
		}
	}
};

InfoBox.prototype.update_display = function() {
	this.display = this.display.data(this.display_info, function(info) {
		return info.hostid;
	});
	var host_div = this.display.enter()
		.append('div')
		.attr('class', 'hostinfo-display');
	host_div.append('p');
	host_div.append('ul');
	this.display.exit()
		.remove();
	this.display.selectAll('p')
		.text(function(d) { return d.host; });
	var tlv = this.display.select('ul').selectAll('li')
		.data(function(d) { return d.tlvs; },
	              function(d) { return d.type; });
	var li = tlv.enter().append('li');
	li.append('span').attr('class', 'type');
	li.append('span').attr('class', 'value');
	tlv.exit().remove();

	tlv.selectAll('span.type').text(function(d) { return d.type + ': ' });
	tlv.selectAll('span.value').text(function(d) { return d.value; });
};

/* Main code starts here */

var container = d3.select('body')
		.style('overflow', 'hidden')
		.append('div')
		.attr('class', 'container');

var infobox = container.append('div')
		.attr('class', 'infobox');

var svg = container.append('svg')
		.attr('class', 'svg-content-responsive');


var defs = svg.append('defs');

var filter_solid = defs.append('filter')
	.attr('x', 0)
	.attr('y', 0)
	.attr('width', 1)
	.attr('height', 1)
	.attr('id', 'solid');

filter_solid.append('feFlood')
	.attr('flood-color', 'white');
filter_solid.append('feComposite')
	.attr('in', 'SourceGraphic');

var vis = new Visual(svg);
var info = new InfoBox(infobox);
