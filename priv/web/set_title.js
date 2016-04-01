var req = new XMLHttpRequest();

req.onreadystatechange = function() {
	if (req.readyState === XMLHttpRequest.DONE && req.status === 200)
		document.title += ' on ' + req.responseText;
};

req.open('GET', '/title');
req.send();
