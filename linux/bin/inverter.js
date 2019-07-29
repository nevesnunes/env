var fs = require('fs');

(function() {
    'use strict';

    var HSVToRGB = function(h, s, v) {
        var r, g, b, i, f, p, q, t;
        if (arguments.length === 1) {
            s = h.s, v = h.v, h = h.h;
        }
        i = Math.floor(h * 6);
        f = h * 6 - i;
        p = v * (1 - s);
        q = v * (1 - f * s);
        t = v * (1 - (1 - f) * s);
        switch (i % 6) {
            case 0:
                r = v, g = t, b = p;
                break;
            case 1:
                r = q, g = v, b = p;
                break;
            case 2:
                r = p, g = v, b = t;
                break;
            case 3:
                r = p, g = q, b = v;
                break;
            case 4:
                r = t, g = p, b = v;
                break;
            case 5:
                r = v, g = p, b = q;
                break;
        }
        return {
            r: Math.round(r * 255),
            g: Math.round(g * 255),
            b: Math.round(b * 255)
        };
    };

    var RGBToHSV = function(r, g, b) {
        if (arguments.length === 1) {
            g = r.g, b = r.b, r = r.r;
        }
        var max = Math.max(r, g, b),
            min = Math.min(r, g, b),
            d = max - min,
            h,
            s = (max === 0 ? 0 : d / max),
            v = max / 255;

        switch (max) {
            case min:
                h = 0;
                break;
            case r:
                h = (g - b) + d * (g < b ? 6 : 0);
                h /= 6 * d;
                break;
            case g:
                h = (b - r) + d * 2;
                h /= 6 * d;
                break;
            case b:
                h = (r - g) + d * 4;
                h /= 6 * d;
                break;
        }

        return {
            h: h,
            s: s,
            v: v
        };
    };

    var componentToHex = function(c) {
        var hex = c.toString(16);
        return hex.length == 1 ? "0" + hex : hex;
    };

    var RGBToHex = function(r, g, b) {
        return "#" +
            componentToHex(r) + componentToHex(g) + componentToHex(b);
    };

    var hexToRGB = function(hex) {
        var result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
        return result ? {
            r: parseInt(result[1], 16),
            g: parseInt(result[2], 16),
            b: parseInt(result[3], 16)
        } : null;
    };

    // Read file contents from argument
    var args = process.argv.slice(2);
    var file = args[0];
    fs.readFile(file, 'utf8', function(err, data) {
        if (err)
            throw err;

        // Save all matches of color codes
        var regex = new RegExp("#[0-9a-f]{6}", "gi");
        var match;
        var matches = [];
        while ((match = regex.exec(data))) {
            matches.push(match[0]);
        }

        // Replace matches with inverted color
        var replacedData = data;
        matches.forEach(function(color) {
            let hsvColor = RGBToHSV(hexToRGB(color));
            //hsvColor.v = 1.0 - hsvColor.v;
            //if (hsvColor.v < 0.9)
            //    hsvColor.v += 0.025;
            if (hsvColor.v > 0.1)
                hsvColor.v -= 0.025;
            let rgbColor = HSVToRGB(hsvColor);
            let secondColor = RGBToHex(rgbColor.r, rgbColor.g, rgbColor.b);

            replacedData = replacedData.replace(color, secondColor);
        });

        // Write changes
        fs.writeFile(
                file + (new Date().getTime()),
                replacedData,
                'utf8',
                function(err) {
            if (err) {
                throw err;
            }
        });
    });
}());
