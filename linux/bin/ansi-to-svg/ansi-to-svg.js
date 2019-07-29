const ansiToSVG = require('ansi-to-svg')
const fs = require('fs');

const args = process.argv.slice(2);
const file = args[0];
fs.readFile(file, 'utf8', function(err, ansiText) {
    if (err) {
        return console.log(err);
    }
    const svgText = ansiToSVG(ansiText, {
        // Defaults to  2x for Retina compatibility
        scale: 2,

        // Font settings
        fontFamily: 'Px437 IBM VGA8',
        fontSize: 14,
        lineHeight: 18,

        colors: {
            black: '#000000',
            red: '#B22222',
            green: '#32CD32',
            yellow: '#DAA520',
            blue: '#4169E1',
            magenta: '#9932CC',
            cyan: '#008B8B',
            white: '#D3D3D3',
            gray: '#A9A9A9',
            redBright: '#FF4500',
            greenBright: '#ADFF2F',
            yellowBright: '#FFFF00',
            blueBright: '#87CEEB',
            magentaBright: '#FF00FF',
            cyanBright: '#00FFFF',
            whiteBright: '#FFFFFF',
            bgBlack: '#000000',
            bgRed: '#B22222',
            bgGreen: '#32CD32',
            bgYellow: '#DAA520',
            bgBlue: '#4169E1',
            bgMagenta: '#9932CC',
            bgCyan: '#008B8B',
            bgWhite: '#D3D3D3',
            bgGray: '#A9A9A9',
            bgRedBright: '#FF0000',
            bgGreenBright: '#ADFF2F',
            bgYellowBright: '#FFFF00',
            bgBlueBright: '#87CEEB',
            bgMagentaBright: '#FF00FF',
            bgCyanBright: '#00FFFF',
            bgWhiteBright: '#FFFFFF',
            backgroundColor: '#000000',
            foregroundColor: '#D3D3D3'
        }
    });
    fs.writeFile("output.svg", svgText, function(err) {
        if (err) {
            return console.log(err);
        }
    });
});
