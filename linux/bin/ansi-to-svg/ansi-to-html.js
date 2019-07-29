const Convert = require('ansi-to-html')
const convert = new Convert();
const fs = require('fs');

const args = process.argv.slice(2);
const file = args[0];
fs.readFile(file, 'utf8', function(err, ansiText) {
    if (err) {
        return console.log(err);
    }
    const htmlText = convert.toHtml(ansiText);
    fs.writeFile("output.html", htmlText, function(err) {
        if (err) {
            return console.log(err);
        }
    });
});
