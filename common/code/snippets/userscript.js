var script = document.createElement('script');
script.appendChild(document.createTextNode('('+ main +')();'));
(document.body || document.head || document.documentElement).appendChild(script);
