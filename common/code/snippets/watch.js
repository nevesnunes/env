// Simplistic directory watcher
//
// example usage:
//
//     $ node watch.js | while read line ; ( while read -r -t 0; do read -r  ; done  ) ; do make ; done
//


var fs = require('fs');

console.log('listening for changes in src/');
fs.watch('src/', {persistent: true, recursive: true}, function (event, fname) {
  console.log(event, fname);
});
