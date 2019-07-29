console.trace();
console.log(new Error().stack);

eval('console.log((function() { return !this; })());')
eval('"use strict"; console.log((function() { return !this; })());')

# heap

node --max-old-space-size=4096

# csp w/ 3rd party scripts

<% response.setHeader("Content-Security-Policy", "style-src 'unsafe-inline' 'self' https://cdn.cookielaw.org; frame-ancestors 'self'; default-src 'unsafe-inline' 'self' data: https://cdn.cookielaw.org https://code.jquery.com https://geolocation.onetrust.com;"); %>

# tasks

grunt --verbose --debug
grunt --gruntfile app/templates/Gruntfile.js --base .

# execute

npx some-package
~=
npm install some-package
./node_modules/.bin/some-package

