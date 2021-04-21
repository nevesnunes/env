const esprima = require('esprima');
const fs = require('fs')

function isDecodeFuncName(node) {
    return (node.type === 'MemberExpression')
         && (node.object.name === 'A1aa')
}

const entries = [];

function printCalls(source) {
    esprima.parseScript(source, {}, function (node, meta) {
        if (isDecodeFuncName(node)) {
            const call = source.substring(meta.start.offset, meta.end.offset).substr(source.indexOf('.') + 1)
            console.log(`Found decode func: ${call}`)
            entries.push(call)
        }
    });
}

function isDecodeCall(node) {
    return (node.type === 'CallExpression') &&
            (node.callee && node.callee.property) &&
            (entries.includes(node.callee.property.name))
}

function replaceCalls(source) {
    const calls = [];
    let finalsource = source;
    esprima.parseScript(source, {}, function(node, meta) {
        if(isDecodeCall(node)) {
            if(node.arguments && node.arguments.length > 0 && typeof node.arguments[0].value !== 'undefined') {
                calls.push({
                    start: meta.start.offset,
                    end: meta.end.offset,
                    param: node.arguments[0].value
                });
                console.log('Found decode call with argument ' + node.arguments[0].value)
            }
        }
    })

    calls.forEach(call => {
        const val = eval(decodefuncs + 'A1aa.W4p(' + call.param + ')')
        console.log(`Replacing ${source.substring(call.start, call.end)} with ${val}`)
        finalsource = finalsource.replace(source.substring(call.start, call.end), `'${val}'`);
    })
    fs.writeFile("finalsrc.js", finalsource, err => {
        if(err) {
            return console.log(err);
        }
        console.log("Saved final source.");
    });
}

let decodefuncs = `A1aa.K3U = function() {
    return typeof A1aa.N3U.T2 === 'function' ? A1aa.N3U.T2.apply(A1aa.N3U, arguments) : A1aa.N3U.T2;
};
A1aa.g3U = function() {
    return typeof A1aa.N3U.C8 === 'function' ? A1aa.N3U.C8.apply(A1aa.N3U, arguments) : A1aa.N3U.C8;
};

function A1aa() {}
A1aa.p8n = function() {
    return typeof A1aa.j8n.x8 === 'function' ? A1aa.j8n.x8.apply(A1aa.j8n, arguments) : A1aa.j8n.x8;
};
A1aa.O4p = function() {
    return typeof A1aa.n4p.T2 === 'function' ? A1aa.n4p.T2.apply(A1aa.n4p, arguments) : A1aa.n4p.T2;
};
A1aa.F3U = function() {
    return typeof A1aa.N3U.d3 === 'function' ? A1aa.N3U.d3.apply(A1aa.N3U, arguments) : A1aa.N3U.d3;
};
A1aa.K4p = function() {
    return typeof A1aa.n4p.x8 === 'function' ? A1aa.n4p.x8.apply(A1aa.n4p, arguments) : A1aa.n4p.x8;
};
A1aa.E4p = function() {
    return typeof A1aa.n4p.d3 === 'function' ? A1aa.n4p.d3.apply(A1aa.n4p, arguments) : A1aa.n4p.d3;
};
A1aa.b8n = function() {
    return typeof A1aa.j8n.d3 === 'function' ? A1aa.j8n.d3.apply(A1aa.j8n, arguments) : A1aa.j8n.d3;
};
A1aa.T8n = function() {
    return typeof A1aa.j8n.x8 === 'function' ? A1aa.j8n.x8.apply(A1aa.j8n, arguments) : A1aa.j8n.x8;
};
A1aa.N3U = function() {
    var r3U = 2;
    for (; r3U !== 1;) {
        switch (r3U) {
            case 2:
                return {
                    T2: function R3U(b3U, m3U) {
                        var G3U = 2;
                        for (; G3U !== 10;) {
                            switch (G3U) {
                                case 12:
                                    L3U += 1;
                                    G3U = 8;
                                    break;
                                case 2:
                                    var O3U = [];
                                    G3U = 1;
                                    break;
                                case 4:
                                    O3U[(H3U + m3U) % b3U] = [];
                                    G3U = 3;
                                    break;
                                case 7:
                                    var I3U = b3U - 1;
                                    G3U = 6;
                                    break;
                                case 3:
                                    H3U += 1;
                                    G3U = 5;
                                    break;
                                case 8:
                                    G3U = L3U < b3U ? 7 : 11;
                                    break;
                                case 9:
                                    var L3U = 0;
                                    G3U = 8;
                                    break;
                                case 1:
                                    var H3U = 0;
                                    G3U = 5;
                                    break;
                                case 13:
                                    I3U -= 1;
                                    G3U = 6;
                                    break;
                                case 14:
                                    O3U[L3U][(I3U + m3U * L3U) % b3U] = O3U[I3U];
                                    G3U = 13;
                                    break;
                                case 5:
                                    G3U = H3U < b3U ? 4 : 9;
                                    break;
                                case 11:
                                    return O3U;
                                    break;
                                case 6:
                                    G3U = I3U >= 0 ? 14 : 12;
                                    break;
                            }
                        }
                    }(27, 9)
                };
                break;
        }
    }
}();
A1aa.x3U = function() {
    return typeof A1aa.N3U.x8 === 'function' ? A1aa.N3U.x8.apply(A1aa.N3U, arguments) : A1aa.N3U.x8;
};
A1aa.W3U = function() {
    return typeof A1aa.N3U.x8 === 'function' ? A1aa.N3U.x8.apply(A1aa.N3U, arguments) : A1aa.N3U.x8;
};
A1aa.B4p = function() {
    return typeof A1aa.n4p.x8 === 'function' ? A1aa.n4p.x8.apply(A1aa.n4p, arguments) : A1aa.n4p.x8;
};
A1aa.w8n = function() {
    return typeof A1aa.j8n.C8 === 'function' ? A1aa.j8n.C8.apply(A1aa.j8n, arguments) : A1aa.j8n.C8;
};
A1aa.j8n = function(E8n) {
    return {
        x8: function() {
            var X8n, C8n = arguments;
            switch (E8n) {
                case A1aa.K3U()[17][21]:
                    X8n = C8n[2] + C8n[0] + C8n[1];
                    break;
                case A1aa.e3U()[25][21]:
                    X8n = C8n[0] - C8n[1];
                    break;
                case A1aa.K3U()[10][13][13]:
                    X8n = (C8n[1] - C8n[0] + -C8n[2]) * C8n[4] - C8n[3];
                    break;
                case A1aa.K3U()[9][11]:
                    X8n = C8n[1] * C8n[0];
                    break;
                case A1aa.e3U()[10][2]:
                    X8n = -(C8n[0] / -C8n[1]);
                    break;
                case A1aa.e3U()[13][22]:
                    X8n = C8n[3] * C8n[1] - C8n[2] + C8n[0] + -C8n[4];
                    break;
                case A1aa.K3U()[11][6]:
                    X8n = C8n[3] - C8n[2] + -C8n[1] + -C8n[0];
                    break;
                case A1aa.K3U()[0][18][4][0]:
                    X8n = C8n[1] * C8n[2] - C8n[0];
                    break;
                case A1aa.K3U()[17][13][4]:
                    X8n = C8n[0] + C8n[1];
                    break;
                case A1aa.e3U()[21][1]:
                    X8n = C8n[2] * C8n[0] / C8n[1];
                    break;
                case A1aa.K3U()[23][5][5]:
                    X8n = C8n[1] - C8n[2] * C8n[0];
                    break;
                case A1aa.K3U()[9][19]:
                    X8n = -C8n[0] / C8n[1];
                    break;
                case A1aa.K3U()[12][0]:
                    X8n = C8n[1] / C8n[0];
                    break;
                case A1aa.K3U()[1][5]:
                    X8n = (C8n[3] + C8n[2]) / C8n[0] + C8n[1];
                    break;
                case A1aa.K3U()[24][6]:
                    X8n = C8n[1] * C8n[2] * C8n[0];
                    break;
                case A1aa.K3U()[9][21]:
                    X8n = -C8n[0] - C8n[3] + -C8n[2] + C8n[1];
                    break;
                case A1aa.e3U()[11][25]:
                    X8n = (C8n[1] + C8n[3] + C8n[4]) * C8n[2] / C8n[0];
                    break;
                case A1aa.e3U()[4][17]:
                    X8n = C8n[2] - C8n[0] + -C8n[1] + C8n[3] + C8n[4];
                    break;
                case A1aa.e3U()[1][25]:
                    X8n = C8n[1] * C8n[4] / C8n[2] * C8n[0] - C8n[3];
                    break;
                case A1aa.e3U()[3][10][19]:
                    X8n = (C8n[2] + C8n[1]) * C8n[3] - C8n[0] + -C8n[4];
                    break;
                case A1aa.e3U()[26][0][9]:
                    X8n = C8n[2] - C8n[0] + C8n[1];
                    break;
                case A1aa.e3U()[21][17]:
                    X8n = C8n[2] * (C8n[1] + C8n[0]) - C8n[3];
                    break;
            }
            return X8n;
        },
        C8: function(f8n) {
            E8n = f8n;
        }
    };
}();
A1aa.K8n = function() {
    return typeof A1aa.j8n.C8 === 'function' ? A1aa.j8n.C8.apply(A1aa.j8n, arguments) : A1aa.j8n.C8;
};
A1aa.h8n = function() {
    return typeof A1aa.j8n.d3 === 'function' ? A1aa.j8n.d3.apply(A1aa.j8n, arguments) : A1aa.j8n.d3;
};
A1aa.D3U = function() {
    return typeof A1aa.N3U.C8 === 'function' ? A1aa.N3U.C8.apply(A1aa.N3U, arguments) : A1aa.N3U.C8;
};
A1aa.e3U = function() {
    return typeof A1aa.N3U.T2 === 'function' ? A1aa.N3U.T2.apply(A1aa.N3U, arguments) : A1aa.N3U.T2;
};
A1aa.W4p = function() {
    return typeof A1aa.n4p.d3 === 'function' ? A1aa.n4p.d3.apply(A1aa.n4p, arguments) : A1aa.n4p.d3;
};
A1aa.l8n = function() {
    return typeof A1aa.j8n.T2 === 'function' ? A1aa.j8n.T2.apply(A1aa.j8n, arguments) : A1aa.j8n.T2;
};
A1aa.Y8n = function() {
    return typeof A1aa.j8n.T2 === 'function' ? A1aa.j8n.T2.apply(A1aa.j8n, arguments) : A1aa.j8n.T2;
};
A1aa.p3U = function() {
    return typeof A1aa.N3U.d3 === 'function' ? A1aa.N3U.d3.apply(A1aa.N3U, arguments) : A1aa.N3U.d3;
};
A1aa.H4p = function() {
    return typeof A1aa.n4p.C8 === 'function' ? A1aa.n4p.C8.apply(A1aa.n4p, arguments) : A1aa.n4p.C8;
};
A1aa.G4p = function() {
    return typeof A1aa.n4p.T2 === 'function' ? A1aa.n4p.T2.apply(A1aa.n4p, arguments) : A1aa.n4p.T2;
};
A1aa.u4p = function() {
    return typeof A1aa.n4p.C8 === 'function' ? A1aa.n4p.C8.apply(A1aa.n4p, arguments) : A1aa.n4p.C8;
};
A1aa.n4p = function() {
    var w4p = 2;
    for (; w4p !== 1;) {
        switch (w4p) {
            case 2:
                return {
                    d3: function(x4p) {
                        var m4p = 2;
                        for (; m4p !== 14;) {
                            switch (m4p) {
                                case 1:
                                    var z4p = 0,
                                        J4p = 0;
                                    m4p = 5;
                                    break;
                                case 4:
                                    m4p = J4p === x4p.length ? 3 : 9;
                                    break;
                                case 5:
                                    m4p = z4p < r4p.length ? 4 : 7;
                                    break;
                                case 9:
                                    i4p += String.fromCharCode(r4p.charCodeAt(z4p) ^ x4p.charCodeAt(J4p));
                                    m4p = 8;
                                    break;
                                case 2:
                                    var i4p = '',
                                        r4p = decodeURI("%1E%0B%1C%19f;#:4%224=!/%255f+o%0A%10%02%0Fp%0F%07%1D%1C%06%1D%0C%1C%15%60rp?+%3C?27%0E%220#7%1C,#4r%05p?!04%13;):9r63#*%3E=%07:%22'25f1%22%22%3E%22fbol8%3E%2075l%14%11%17%0Bo%0D%04%02%12%17o!'56%3E,%3Es%18%0D%1E%01%1Ds#!5%20+?$%087#)%258f!%25!&r&3.%256%22+'#*s%04%16%17%08%7Fs%12%0D%1E%01%0C%1E%11%16%16%7D%7Ds%03%0F%0Bo9s463:%0A8#03#-4r%06%1B%01%02%13%1F%05%00%09~%60r!3%3E+%18%3E%0B'9l%02%13%05%1E%08l!561(%20%25r4co=!%22-&(l%01%11%08%1F%12%1A%03%15%01p+%22%3E?6p$%2055%3C%1D+l%1C%15%00%1B%18%03s%12%0D%1E%01%0C%1E%11%16%16%7Dzs&%25%3E8+s%1C%0B%1C%0Al&?6%3E)l#%25*p./?&%25!o%0A%1E%07%0Ap9!%17%3C+39l717&%12%220%20%1B&$#4r%0C%1B%0A%06s?%224%3E+%25r4%3E,74%22f5(:%12?*&(6%25r%16%1B%0A%06%05r%0A%1D%03%0Bs%04%16%17%08%7Cs#47(*%0E&%25%3E8+s3(7,%3C%035'&o%1E%1D%11%1D%17%1F%11%02%04%16%13%04%09%19%04f!9!#1#7o%220#0%0D!/!%0F0;%20+s5%3C%22%22%204%3E0;,%22%17?#p=;%228f3.-4%3C!%20,:4r%08%17%03%09%05%18f%10%04%02%1D%12%0B%13%1F%0Aaef18%3C#5*&%12%220%20%1B&$#4r7%22?'%2557p%1D%07s%22%25%3C)!%3Cr%00p%25'68f%01o+0#!%1B#l%17%19%0A%1B%1E%06s%22+'#*s3%25%20%3El650p%3E+%25r%223%3E:4#0p5l%225#?(%20%25r'3%20+#1%0C7$)9$f%3E(%206$,p7l8%3E'%20(/%225f4%22)%155*!$:(r%17%1A%02%1C%05r%07%1D%01%1B%1C%1Ef%07%1Dl!561(%20%25%02!?,'?9*5o=2%22!7#l%251*p!'%3C90p%01%0B%17%04f%01%19%0F%03%04f'=l%12%11%16%01o9840:o-0=!%20,l%22?1%20.+s%206='+2$f%3E,=%25%0F(3=%11%259)7%1280%3C17o%3C$=&%3E(%024%3E#&%25l79!%3E)%017%06-7:l%19%19%08%1Eo%0C%18%1C%08%10%02%0F%03%14t%60o=!%3C-1(l%25?%0D%3C9l%13%19%08%1E%0F%01%10%02%00bzl2%3C-%22o%0C%18%1C%08%10%02%0F%03%14tko%3C0%3E%20=%20%07?$f%7Co=!5!6o&49#:9l%05%02%01%17%1El2%256$(l%1D%19%03%1A%19l7?#p=%7Cs%3C+==+5r%14%1E%0C%00%05%03f%05o%02%1E%07f%60)l%223%25%3E(l%13%19%08%1E%0F%01%10%02%00bul2%256%20(%20%25%0F(3=%11%259)7%1280%3C17o/54%07%3E,=%22%1E%25?(l%13%19%08%1E%0F%01%10%02%00%01o*%3E'*p!/?57p)!%3Cr%223%3E:%0E%3C%25%22%12:8=!%0D;/=%25!");
                                    m4p = 1;
                                    break;
                                case 3:
                                    J4p = 0;
                                    m4p = 9;
                                    break;
                                case 8:
                                    z4p++, J4p++;
                                    m4p = 5;
                                    break;
                                case 7:
                                    i4p = i4p.split('"');
                                    return function(s4p) {
                                        var f4p = 2;
                                        for (; f4p !== 1;) {
                                            switch (f4p) {
                                                case 2:
                                                    return i4p[s4p];
                                                    break;
                                            }
                                        }
                                    };
                                    break;
                            }
                        }
                    }('MNQPDR')
                };
                break;
        }
    }
}();
`;

const source = `(function() {
    var a3U = A1aa;
    var s1a, j1a, t2, d2, k1a, Y3, n1a, Q1a, c1a, E3, P3, K3, j2, q2, D2, V2, P2, I2, o2, h2, b2, r3, F2, z3, k3, G2, W2, H2, B2, u2, t3, s2, f2, Y2, B1a, b1a, M1a, A1a, r1a, R2, L2, O2, j3, W3, C3, I3, N5;
    s1a = 60;
    a3U.K8n(a3U.e3U()[25][9]);
    j1a = a3U.T8n(s1a, 1);

    function n2(L9a, q9a, w9a, I9a, P9a) {
        var C9a, g9a, G9a, D9a;
        C9a = Z3();
        g9a = C9a + Util[a3U.E4p(103)](P9a, 0) * b2;
        a3U.w8n(a3U.e3U()[5][21]);
        D9a = a3U.p8n(q9a, w9a, L9a);
        for (G9a = 0; G9a < L9a; G9a++) {
            p1a(Util[a3U.E4p(68)](0, I9a, G9a / L9a), Util[a3U.E4p(26)](C9a, g9a, G9a / D9a));
        }
        for (G9a = 0; G9a < q9a; G9a++) {
            p1a(I9a, Util[a3U.W4p(26)](C9a, g9a, (L9a + G9a) / D9a));
        }
        for (G9a = 0; G9a < w9a; G9a++) {
            p1a(Util[a3U.W4p(26)](I9a, 0, G9a / w9a), Util[a3U.W4p(26)](C9a, g9a, (L9a + q9a + G9a) / D9a));
        }
    }
    t2 = 1024;
    d2 = 768;
    k1a = 0.3;
    Y3 = 0.99;
    n1a = 0.001;

    function c3(e9a, f9a) {
        if (I3[e9a][a3U.E4p(36)] !== f9a) {
            I3[e9a][a3U.E4p(36)] = f9a;
            Dom[a3U.E4p(73)](I3[e9a][a3U.E4p(128)], f9a);
        }
    }

    function Z3() {
        return j2[a3U.E4p(78)] == 0 ? 0 : j2[j2[a3U.W4p(78)] - 1][a3U.E4p(115)][a3U.W4p(38)][a3U.E4p(2)];
    }
    Q1a = 0.002;

    function Y1a(P1a, i1a, O1a) {
        var w1a, D1a, q1a, I1a;
        for (w1a = 0; w1a < q2[a3U.E4p(78)]; w1a++) {
            D1a = q2[w1a];
            q1a = J2(D1a[a3U.E4p(79)]);
            D1a[a3U.E4p(45)] = D1a[a3U.W4p(45)] + E1a(D1a, q1a, i1a, O1a);
            D1a[a3U.E4p(79)] = Util[a3U.E4p(80)](D1a[a3U.E4p(79)], P1a * D1a[a3U.W4p(109)], F2);
            D1a[a3U.E4p(28)] = Util[a3U.W4p(85)](D1a[a3U.E4p(79)], b2);
            I1a = J2(D1a[a3U.E4p(79)]);
            if (q1a != I1a) {
                index = q1a[a3U.W4p(71)][a3U.W4p(33)](D1a);
                q1a[a3U.E4p(71)][a3U.E4p(102)](index, 1);
                I1a[a3U.E4p(71)][a3U.W4p(57)](D1a);
            }
        }
    }
    c1a = 0.003;

    function X1a() {
        n2(10, 10, 10, 0, 5);
        n2(10, 10, 10, 0, -2);
        n2(10, 10, 10, 0, -5);
        n2(10, 10, 10, 0, 8);
        n2(10, 10, 10, 0, 5);
        n2(10, 10, 10, 0, -7);
        n2(10, 10, 10, 0, 5);
        n2(10, 10, 10, 0, -2);
    }
    E3 = 0;
    P3 = 0;
    K3 = 0;
    j2 = [];

    function K1a(y9a, z9a) {
        y9a = y9a || N5[a3U.W4p(59)][a3U.W4p(82)];
        z9a = z9a || N5[a3U.E4p(100)][a3U.E4p(119)];
        a3U.w8n(a3U.e3U()[2][18]);
        n2(y9a, y9a, y9a, 0, a3U.p8n(2, z9a));
        n2(y9a, y9a, y9a, 0, -z9a);
        n2(y9a, y9a, y9a, N5[a3U.E4p(14)][a3U.W4p(13)], z9a);
        n2(y9a, y9a, y9a, 0, 0);
        n2(y9a, y9a, y9a, -N5[a3U.W4p(14)][a3U.W4p(13)], z9a / 2);
        n2(y9a, y9a, y9a, 0, 0);
    }
    q2 = [];

    function m1a() {
        n2(N5[a3U.E4p(59)][a3U.E4p(34)], N5[a3U.E4p(59)][a3U.E4p(34)], N5[a3U.E4p(59)][a3U.W4p(34)], -N5[a3U.E4p(14)][a3U.W4p(13)], N5[a3U.W4p(100)][a3U.W4p(49)]);
        n2(N5[a3U.E4p(59)][a3U.E4p(34)], N5[a3U.E4p(59)][a3U.W4p(34)], N5[a3U.W4p(59)][a3U.E4p(34)], N5[a3U.W4p(14)][a3U.W4p(34)], N5[a3U.E4p(100)][a3U.W4p(34)]);
        n2(N5[a3U.W4p(59)][a3U.E4p(34)], N5[a3U.W4p(59)][a3U.E4p(34)], N5[a3U.E4p(59)][a3U.E4p(34)], N5[a3U.W4p(14)][a3U.W4p(13)], -N5[a3U.E4p(100)][a3U.W4p(119)]);
        n2(N5[a3U.E4p(59)][a3U.W4p(34)], N5[a3U.W4p(59)][a3U.E4p(34)], N5[a3U.E4p(59)][a3U.E4p(34)], -N5[a3U.W4p(14)][a3U.E4p(13)], N5[a3U.E4p(100)][a3U.W4p(34)]);
        n2(N5[a3U.E4p(59)][a3U.W4p(34)], N5[a3U.E4p(59)][a3U.E4p(34)], N5[a3U.W4p(59)][a3U.W4p(34)], -N5[a3U.E4p(14)][a3U.E4p(34)], -N5[a3U.E4p(100)][a3U.W4p(34)]);
    }
    D2 = Dom[a3U.E4p(72)](a3U.W4p(40));
    V2 = D2[a3U.W4p(47)](a3U.W4p(120));

    function t1a() {
        var U9a, V9a, s9a, h9a, X9a, u9a, d9a, t9a, B9a, b9a, k9a, K9a, Y9a, M9a, x9a, E9a;
        U9a = J2(s2);
        V9a = Util[a3U.E4p(85)](s2, b2);
        s9a = J2(s2 + u2);
        h9a = Util[a3U.W4p(85)](s2 + u2, b2);
        X9a = Util[a3U.W4p(1)](s9a[a3U.E4p(29)][a3U.W4p(38)][a3U.E4p(2)], s9a[a3U.E4p(115)][a3U.E4p(38)][a3U.E4p(2)], h9a);
        u9a = d2;
        d9a = 0;
        t9a = -(U9a[a3U.E4p(112)] * V9a);
        V2[a3U.E4p(52)](0, 0, t2, d2);
        Render[a3U.W4p(19)](V2, P2, t2, d2, BACKGROUND[a3U.W4p(22)], E3, o2 * n1a * X9a);
        Render[a3U.E4p(19)](V2, P2, t2, d2, BACKGROUND[a3U.E4p(16)], P3, o2 * Q1a * X9a);
        Render[a3U.W4p(19)](V2, P2, t2, d2, BACKGROUND[a3U.W4p(111)], K3, o2 * c1a * X9a);
        for (B9a = 0; B9a < H2; B9a++) {
            k9a = j2[(U9a[a3U.W4p(12)] + B9a) % j2[a3U.E4p(78)]];
            k9a[a3U.E4p(116)] = k9a[a3U.W4p(12)] < U9a[a3U.W4p(12)];
            k9a[a3U.W4p(114)] = Util[a3U.E4p(56)](B9a / H2, t3);
            k9a[a3U.E4p(105)] = u9a;
            Util[a3U.E4p(96)](k9a[a3U.E4p(29)], B2 * h2 - d9a, X9a + G2, s2 - (k9a[a3U.W4p(116)] ? F2 : 0), W2, t2, d2, h2);
            Util[a3U.E4p(96)](k9a[a3U.W4p(115)], B2 * h2 - d9a - t9a, X9a + G2, s2 - (k9a[a3U.W4p(116)] ? F2 : 0), W2, t2, d2, h2);
            d9a = d9a + t9a;
            t9a = t9a + k9a[a3U.E4p(112)];
            if (k9a[a3U.W4p(29)][a3U.E4p(94)][a3U.E4p(79)] <= W2 || k9a[a3U.E4p(115)][a3U.W4p(86)][a3U.E4p(2)] >= k9a[a3U.E4p(29)][a3U.W4p(86)][a3U.W4p(2)] || k9a[a3U.E4p(115)][a3U.E4p(86)][a3U.W4p(2)] >= u9a) continue;
            Render[a3U.W4p(76)](V2, t2, z3, k9a[a3U.W4p(29)][a3U.E4p(86)][a3U.W4p(75)], k9a[a3U.E4p(29)][a3U.E4p(86)][a3U.E4p(2)], k9a[a3U.W4p(29)][a3U.W4p(86)][a3U.E4p(23)], k9a[a3U.W4p(115)][a3U.E4p(86)][a3U.W4p(75)], k9a[a3U.E4p(115)][a3U.E4p(86)][a3U.W4p(2)], k9a[a3U.W4p(115)][a3U.E4p(86)][a3U.W4p(23)], k9a[a3U.W4p(114)], k9a[a3U.W4p(9)]);
            u9a = k9a[a3U.E4p(29)][a3U.E4p(86)][a3U.W4p(2)];
        }
        for (B9a = H2 - 1; B9a > 0; B9a--) {
            k9a = j2[(U9a[a3U.W4p(12)] + B9a) % j2[a3U.E4p(78)]];
            for (b9a = 0; b9a < k9a[a3U.E4p(71)][a3U.W4p(78)]; b9a++) {
                K9a = k9a[a3U.E4p(71)][b9a];
                Y9a = K9a[a3U.E4p(30)];
                M9a = Util[a3U.W4p(1)](k9a[a3U.E4p(29)][a3U.W4p(86)][a3U.W4p(121)], k9a[a3U.E4p(115)][a3U.E4p(86)][a3U.W4p(121)], K9a[a3U.E4p(28)]);
                x9a = Util[a3U.E4p(1)](k9a[a3U.E4p(29)][a3U.W4p(86)][a3U.W4p(75)], k9a[a3U.W4p(115)][a3U.W4p(86)][a3U.W4p(75)], K9a[a3U.E4p(28)]) + M9a * K9a[a3U.W4p(45)] * h2 * t2 / 2;
                E9a = Util[a3U.W4p(1)](k9a[a3U.E4p(29)][a3U.E4p(86)][a3U.E4p(2)], k9a[a3U.W4p(115)][a3U.E4p(86)][a3U.W4p(2)], K9a[a3U.W4p(28)]);
                Render[a3U.W4p(30)](V2, t2, d2, o2, h2, I2, K9a[a3U.E4p(30)], M9a, x9a, E9a, -0.5, -1, k9a[a3U.W4p(105)]);
            }
            for (b9a = 0; b9a < k9a[a3U.W4p(62)][a3U.W4p(78)]; b9a++) {
                Y9a = k9a[a3U.W4p(62)][b9a];
                M9a = k9a[a3U.W4p(29)][a3U.E4p(86)][a3U.W4p(121)];
                x9a = k9a[a3U.W4p(29)][a3U.E4p(86)][a3U.W4p(75)] + M9a * Y9a[a3U.W4p(45)] * h2 * t2 / 2;
                E9a = k9a[a3U.E4p(29)][a3U.W4p(86)][a3U.W4p(2)];
                Render[a3U.E4p(30)](V2, t2, d2, o2, h2, I2, Y9a[a3U.E4p(95)], M9a, x9a, E9a, Y9a[a3U.W4p(45)] < 0 ? -1 : 0, -1, k9a[a3U.W4p(105)]);
            }
            if (k9a == s9a) {
                Render[a3U.E4p(46)](V2, t2, d2, o2, h2, I2, f2 / Y2, W2 / u2, t2 / 2, d2 / 2 - W2 / u2 * Util[a3U.W4p(1)](s9a[a3U.E4p(29)][a3U.W4p(94)][a3U.W4p(2)], s9a[a3U.W4p(115)][a3U.E4p(94)][a3U.E4p(2)], h9a) * d2 / 2, f2 * (O2 ? -1 : j3 ? 1 : 0), s9a[a3U.W4p(115)][a3U.E4p(38)][a3U.W4p(2)] - s9a[a3U.W4p(29)][a3U.E4p(38)][a3U.W4p(2)]);
            }
        }
    }

    function x1a() {
        j2 = [];
        e1a(N5[a3U.E4p(59)][a3U.W4p(82)]);
        K1a();
        m1a();
        X3(N5[a3U.W4p(59)][a3U.E4p(34)], N5[a3U.E4p(14)][a3U.W4p(34)], N5[a3U.W4p(100)][a3U.E4p(119)]);
        X1a();
        K1a();
        X3(N5[a3U.W4p(59)][a3U.W4p(37)] * 2, N5[a3U.E4p(14)][a3U.E4p(34)], N5[a3U.W4p(100)][a3U.E4p(34)]);
        e1a();
        f1a(N5[a3U.E4p(59)][a3U.W4p(34)], N5[a3U.W4p(100)][a3U.W4p(44)]);
        m1a();
        X3(N5[a3U.E4p(59)][a3U.W4p(37)], -N5[a3U.E4p(14)][a3U.E4p(34)], N5[a3U.W4p(100)][a3U.W4p(49)]);
        f1a(N5[a3U.E4p(59)][a3U.W4p(37)], N5[a3U.E4p(100)][a3U.W4p(44)]);
        X3(N5[a3U.E4p(59)][a3U.W4p(37)], N5[a3U.W4p(14)][a3U.W4p(34)], -N5[a3U.W4p(100)][a3U.W4p(119)]);
        X1a();
        f1a(N5[a3U.W4p(59)][a3U.E4p(37)], -N5[a3U.W4p(100)][a3U.W4p(34)]);
        e1a();
        m1a();
        u1a();
        h1a();
        V1a();
        a3U.w8n(a3U.e3U()[16][21]);
        var R4p = a3U.T8n(31, 19);
        a3U.K8n(a3U.K3U()[3][18]);
        var D4p = a3U.p8n(62, 4, 16);
        j2[J2(u2)[a3U.E4p(R4p)] + D4p][a3U.E4p(9)] = COLORS[a3U.E4p(90)];
        a3U.w8n(a3U.e3U()[24][0]);
        var o4p = a3U.p8n(2, 24);
        a3U.K8n(a3U.e3U()[16][3]);
        var a4p = a3U.p8n(2, 32, 14, 13);
        j2[J2(u2)[a3U.W4p(o4p)] + a4p][a3U.W4p(9)] = COLORS[a3U.E4p(90)];
        for (var Z9a = 0; Z9a < r3; Z9a++) {
            a3U.K8n(a3U.e3U()[13][5][14]);
            var F4p = a3U.T8n(3, 67, 13, 20);
            a3U.w8n(a3U.e3U()[24][10]);
            var A4p = a3U.p8n(4, 1, 20, 17, 352);
            j2[j2[a3U.E4p(F4p)] - A4p - Z9a][a3U.W4p(9)] = COLORS[a3U.E4p(69)];
        }
        a3U.K8n(a3U.K3U()[15][22]);
        var h4p = a3U.T8n(72, 6);
        F2 = j2[a3U.E4p(h4p)] * b2;
    }

    function J2(J9a) {
        a3U.K8n(a3U.K3U()[26][7]);
        var L4p = a3U.T8n(15, 1482, 18, 11037, 9);
        return j2[Math[a3U.E4p(32)](J9a / b2) % j2[a3U.W4p(L4p)]];
    }
    P2 = null;
    I2 = null;
    o2 = a3U.E4p(66);
    h2 = 2000;
    b2 = 200;
    r3 = 3;
    F2 = null;

    function d1a(W1a) {
        var l1a, F1a, g1a, R1a, L1a, J1a, G1a, C1a, H1a, o1a;
        a3U.w8n(a3U.e3U()[16][4]);
        J1a = J2(a3U.T8n(s2, u2));
        a3U.w8n(a3U.K3U()[8][0]);
        var c4p = a3U.p8n(20, 7, 66);
        a3U.K8n(a3U.e3U()[20][3]);
        var S4p = a3U.p8n(92, 69);
        G1a = SPRITES[a3U.W4p(c4p)][a3U.W4p(S4p)] * SPRITES[a3U.E4p(27)];
        a3U.w8n(a3U.e3U()[19][9]);
        C1a = a3U.p8n(Y2, f2);
        a3U.w8n(a3U.e3U()[14][24]);
        H1a = a3U.T8n(C1a, W1a, 2);
        o1a = s2;
        Y1a(W1a, J1a, G1a);
        s2 = Util[a3U.E4p(80)](s2, a3U.p8n(f2, W1a, a3U.w8n(a3U.K3U()[2][2])), F2);
        if (O2) {
            a3U.w8n(a3U.e3U()[3][12]);
            B2 = a3U.T8n(B2, H1a);
        } else if (j3) {
            a3U.K8n(a3U.e3U()[3][22]);
            B2 = a3U.p8n(B2, H1a);
        }
        a3U.w8n(a3U.e3U()[23][22]);
        var N4p = a3U.p8n(2, 1792, 19, 24682, 14);
        B2 = B2 - H1a * C1a * J1a[a3U.E4p(N4p)] * k1a;
        if (W3) {
            f2 = Util[a3U.E4p(58)](f2, B1a, W1a);
        } else if (C3) {
            f2 = Util[a3U.W4p(58)](f2, b1a, W1a);
        } else {
            f2 = Util[a3U.E4p(58)](f2, M1a, W1a);
        }
        if (B2 < -1 || B2 > 1) {
            if (f2 > A1a) {
                f2 = Util[a3U.E4p(58)](f2, Y3, W1a);
            }
            for (l1a = 0; l1a < J1a[a3U.E4p(62)][a3U.E4p(78)]; l1a++) {
                R1a = J1a[a3U.E4p(62)][l1a];
                a3U.K8n(a3U.e3U()[17][0][9]);
                var k4p = a3U.p8n(1047, 2, 1140);
                a3U.K8n(a3U.K3U()[23][4]);
                var y4p = a3U.p8n(16, 45, 5, 9, 389);
                L1a = R1a[a3U.W4p(k4p)][a3U.E4p(23)] * SPRITES[a3U.E4p(y4p)];
                if (Util[a3U.E4p(15)](B2, G1a, R1a[a3U.W4p(45)] + L1a / 2 * (R1a[a3U.E4p(45)] > 0 ? 1 : -1), L1a)) {
                    a3U.w8n(a3U.e3U()[13][9]);
                    f2 = a3U.p8n(5, Y2);
                    s2 = Util[a3U.E4p(80)](J1a[a3U.W4p(29)][a3U.E4p(38)][a3U.W4p(79)], -u2, F2);
                    break;
                }
            }
        }
        for (l1a = 0; l1a < J1a[a3U.W4p(71)][a3U.W4p(78)]; l1a++) {
            F1a = J1a[a3U.W4p(71)][l1a];
            a3U.w8n(a3U.e3U()[1][4]);
            var g4p = a3U.p8n(28, 2);
            a3U.K8n(a3U.e3U()[11][13]);
            var C4p = a3U.p8n(13, 10);
            g1a = F1a[a3U.W4p(g4p)][a3U.W4p(C4p)] * SPRITES[a3U.E4p(27)];
            if (f2 > F1a[a3U.E4p(109)]) {
                if (Util[a3U.W4p(15)](B2, G1a, F1a[a3U.W4p(45)], g1a, 0.8)) {
                    f2 = F1a[a3U.W4p(109)] * (F1a[a3U.E4p(109)] / f2);
                    s2 = Util[a3U.W4p(80)](F1a[a3U.W4p(79)], -u2, F2);
                    break;
                }
            }
        }
        B2 = Util[a3U.E4p(88)](B2, -3, 3);
        f2 = Util[a3U.E4p(88)](f2, 0, Y2);
        E3 = Util[a3U.E4p(80)](E3, n1a * J1a[a3U.W4p(112)] * (s2 - o1a) / b2, 1);
        P3 = Util[a3U.W4p(80)](P3, Q1a * J1a[a3U.W4p(112)] * (s2 - o1a) / b2, 1);
        K3 = Util[a3U.W4p(80)](K3, c1a * J1a[a3U.E4p(112)] * (s2 - o1a) / b2, 1);
        if (s2 > u2) {
            if (R2 && o1a < u2) {
                L2 = R2;
                R2 = 0;
                if (L2 <= Util[a3U.W4p(42)](Dom[a3U.W4p(54)][a3U.W4p(43)])) {
                    Dom[a3U.W4p(54)][a3U.E4p(43)] = L2;
                    c3(a3U.W4p(43), i3(L2));
                    Dom[a3U.W4p(124)](a3U.E4p(43), a3U.E4p(74));
                    Dom[a3U.E4p(124)](a3U.W4p(55), a3U.E4p(74));
                } else {
                    Dom[a3U.W4p(5)](a3U.E4p(43), a3U.E4p(74));
                    Dom[a3U.E4p(5)](a3U.E4p(55), a3U.E4p(74));
                }
                c3(a3U.W4p(55), i3(L2));
                Dom[a3U.W4p(18)](a3U.W4p(55));
            } else {
                R2 += W1a;
            }
        }
        c3(a3U.W4p(109), 5 * Math[a3U.W4p(70)](f2 / 500));
        c3(a3U.W4p(61), i3(R2));
    }

    function U1a(b0a) {
        b0a = b0a || {};
        D2[a3U.E4p(93)] = t2 = Util[a3U.W4p(103)](b0a[a3U.E4p(93)], t2);
        D2[a3U.E4p(110)] = d2 = Util[a3U.W4p(103)](b0a[a3U.E4p(110)], d2);
        z3 = Util[a3U.W4p(103)](b0a[a3U.E4p(127)], z3);
        h2 = Util[a3U.E4p(103)](b0a[a3U.W4p(7)], h2);
        G2 = Util[a3U.W4p(103)](b0a[a3U.W4p(77)], G2);
        H2 = Util[a3U.E4p(103)](b0a[a3U.W4p(24)], H2);
        t3 = Util[a3U.E4p(103)](b0a[a3U.E4p(81)], t3);
        k3 = Util[a3U.W4p(103)](b0a[a3U.W4p(99)], k3);
        b2 = Util[a3U.E4p(103)](b0a[a3U.E4p(17)], b2);
        r3 = Util[a3U.W4p(103)](b0a[a3U.E4p(98)], r3);
        a3U.w8n(a3U.K3U()[7][2]);
        var q3p = a3U.T8n(19, 19);
        a3U.K8n(a3U.e3U()[15][17]);
        var t3p = a3U.T8n(6, 22, 56, 1566);
        a3U.w8n(a3U.K3U()[9][18]);
        var U3p = a3U.T8n(717, 60, 13);
        a3U.K8n(a3U.e3U()[18][7]);
        var P3p = a3U.p8n(66, 2340, 5, 17, 19);
        W2 = q3p / Math[a3U.E4p(87)](k3 / t3p * Math[a3U.W4p(U3p)] / P3p);
        a3U.K8n(a3U.K3U()[19][20]);
        u2 = a3U.p8n(W2, G2);
        a3U.w8n(a3U.e3U()[7][9]);
        o2 = a3U.T8n(480, d2);
        if (j2[a3U.W4p(78)] == 0 || b0a[a3U.W4p(17)] || b0a[a3U.W4p(98)]) {
            x1a();
        }
    }
    z3 = 3;
    k3 = 100;
    G2 = 1000;

    function p1a(W9a, F9a) {
        var l9a;
        l9a = j2[a3U.W4p(78)];
        j2[a3U.E4p(57)]({
            'index': l9a,
            'p1': {
                'world': {
                    'y': Z3(),
                    'z': l9a * b2
                },
                'camera': {},
                'screen': {}
            },
            'p2': {
                'world': {
                    'y': F9a,
                    'z': (l9a + 1) * b2
                },
                'camera': {},
                'screen': {}
            },
            'curve': W9a,
            'sprites': [],
            'cars': [],
            'color': Math[a3U.W4p(32)](l9a / r3) % 2 ? COLORS[a3U.W4p(3)] : COLORS[a3U.E4p(113)]
        });
    }
    W2 = null;
    H2 = 300;
    B2 = 0;

    function i3(n9a) {
        var m9a, A9a, r9a;
        m9a = Math[a3U.W4p(32)](a3U.p8n(60, n9a, a3U.K8n(a3U.K3U()[21][0])));
        A9a = Math[a3U.E4p(32)](a3U.T8n(60, n9a, m9a, a3U.K8n(a3U.e3U()[8][5])));
        r9a = Math[a3U.E4p(32)](10 * (n9a - Math[a3U.E4p(32)](n9a)));
        if (m9a > 0) {
            a3U.w8n(a3U.e3U()[2][6]);
            var T3p = a3U.p8n(1044, 20, 16, 1188);
            a3U.w8n(a3U.e3U()[12][1][10]);
            var p3p = a3U.p8n(6, 18, 30);
            a3U.K8n(a3U.e3U()[7][4]);
            var v3p = a3U.p8n(10, 1);
            return m9a + a3U.W4p(T3p) + (A9a < p3p ? a3U.W4p(10) : a3U.W4p(v3p)) + A9a + a3U.E4p(108) + r9a;
        } else {
            a3U.K8n(a3U.e3U()[3][8][26]);
            var Z3p = a3U.T8n(16, 36, 123, 19, 18);
            return A9a + a3U.E4p(Z3p) + r9a;
        }
    }
    u2 = null;
    t3 = 5;

    function h1a() {
        var p0a, j0a, c0a, Q0a, e0a;
        A2(20, SPRITES[a3U.W4p(104)], -1);
        A2(40, SPRITES[a3U.W4p(4)], -1);
        A2(60, SPRITES[a3U.W4p(122)], -1);
        A2(80, SPRITES[a3U.W4p(106)], -1);
        A2(100, SPRITES[a3U.E4p(25)], -1);
        A2(120, SPRITES[a3U.E4p(101)], -1);
        A2(140, SPRITES[a3U.W4p(21)], -1);
        A2(160, SPRITES[a3U.E4p(35)], -1);
        A2(180, SPRITES[a3U.W4p(60)], -1);
        A2(240, SPRITES[a3U.W4p(104)], -1.2);
        A2(240, SPRITES[a3U.E4p(4)], 1.2);
        A2(j2[a3U.E4p(78)] - 25, SPRITES[a3U.W4p(104)], -1.2);
        A2(j2[a3U.E4p(78)] - 25, SPRITES[a3U.E4p(4)], 1.2);
        for (p0a = 10; p0a < 200; p0a += 4 + Math[a3U.E4p(32)](p0a / 100)) {
            A2(p0a, SPRITES[a3U.E4p(31)], 0.5 + Math[a3U.W4p(64)]() * 0.5);
            A2(p0a, SPRITES[a3U.E4p(31)], 1 + Math[a3U.W4p(64)]() * 2);
        }
        for (p0a = 250; p0a < 1000; p0a += 5) {
            A2(p0a, SPRITES[a3U.W4p(83)], 1.1);
            A2(p0a + Util[a3U.E4p(107)](0, 5), SPRITES[a3U.W4p(20)], -1 - Math[a3U.E4p(64)]() * 2);
            A2(p0a + Util[a3U.W4p(107)](0, 5), SPRITES[a3U.W4p(50)], -1 - Math[a3U.W4p(64)]() * 2);
        }
        for (p0a = 200; p0a < j2[a3U.W4p(78)]; p0a += 3) {
            A2(p0a, Util[a3U.W4p(8)](SPRITES[a3U.W4p(117)]), Util[a3U.W4p(8)]([1, -1]) * (2 + Math[a3U.W4p(64)]() * 5));
        }
        for (p0a = 1000; p0a < j2[a3U.E4p(78)] - 50; p0a += 100) {
            c0a = Util[a3U.E4p(8)]([1, -1]);
            A2(p0a + Util[a3U.W4p(107)](0, 50), Util[a3U.W4p(8)](SPRITES[a3U.W4p(125)]), -c0a);
            for (j0a = 0; j0a < 20; j0a++) {
                Q0a = Util[a3U.E4p(8)](SPRITES[a3U.W4p(117)]);
                e0a = c0a * (1.5 + Math[a3U.E4p(64)]());
                A2(p0a + Util[a3U.E4p(107)](0, 50), Q0a, e0a);
            }
        }
    }
    s2 = 0;
    f2 = 0;

    function V1a() {
        var f0a, n0a, A0a, r0a, k0a, m0a, B0a;
        q2 = [];
        for (var f0a = 0; f0a < r1a; f0a++) {
            a3U.K8n(a3U.e3U()[0][19][12][19]);
            var l3p = a3U.T8n(4, 5);
            r0a = Math[a3U.E4p(64)]() * Util[a3U.W4p(8)]([l3p, 0.8]);
            k0a = Math[a3U.E4p(32)](Math[a3U.E4p(64)]() * j2[a3U.W4p(78)]) * b2;
            m0a = Util[a3U.W4p(8)](SPRITES[a3U.E4p(92)]);
            a3U.w8n(a3U.e3U()[17][19]);
            var M3p = a3U.p8n(5, 15, 12);
            a3U.w8n(a3U.e3U()[1][9]);
            var i3p = a3U.T8n(8, 16);
            B0a = Y2 / M3p + Math[a3U.W4p(64)]() * Y2 / (m0a == SPRITES[a3U.W4p(0)] ? 4 : i3p);
            n0a = {
                'offset': r0a,
                'z': k0a,
                'sprite': m0a,
                'speed': B0a
            };
            A0a = J2(n0a[a3U.W4p(79)]);
            A0a[a3U.E4p(71)][a3U.E4p(57)](n0a);
            q2[a3U.E4p(57)](n0a);
        }
    }
    a3U.w8n(a3U.e3U()[23][18]);
    Y2 = a3U.T8n(j1a, b2);

    function u1a(a9a) {
        a9a = a9a || 200;
        n2(a9a, a9a, a9a, -N5[a3U.E4p(14)][a3U.W4p(13)], -Z3() / b2);
    }
    a3U.w8n(a3U.e3U()[8][18]);
    B1a = a3U.p8n(5, Y2);
    b1a = -Y2;

    function X3(T9a, S9a, N9a) {
        T9a = T9a || N5[a3U.W4p(59)][a3U.E4p(34)];
        S9a = S9a || N5[a3U.W4p(14)][a3U.E4p(34)];
        N9a = N9a || N5[a3U.W4p(100)][a3U.E4p(49)];
        n2(T9a, T9a, T9a, S9a, N9a);
    }
    a3U.w8n(a3U.K3U()[14][10]);
    M1a = a3U.T8n(Y2, 5);
    a3U.w8n(a3U.e3U()[20][10]);
    Y3 = a3U.p8n(Y2, 2);

    function A2(o9a, H9a, R9a) {
        j2[o9a][a3U.E4p(62)][a3U.E4p(57)]({
            'source': H9a,
            'offset': R9a
        });
    }
    a3U.K8n(a3U.e3U()[16][9]);
    A1a = a3U.p8n(4, Y2);
    r1a = 200;

    function E1a(v1a, p9a, Z1a, Q9a) {
        var N1a, y1a, S1a, z1a, T1a, j9a, c9a, a1a;
        c9a = 20;
        a1a = v1a[a3U.E4p(30)][a3U.W4p(23)] * SPRITES[a3U.W4p(27)];
        if (p9a[a3U.W4p(12)] - Z1a[a3U.E4p(12)] > H2) return 0;
        for (N1a = 1; N1a < c9a; N1a++) {
            z1a = j2[(p9a[a3U.E4p(12)] + N1a) % j2[a3U.W4p(78)]];
            if (z1a === Z1a && v1a[a3U.W4p(109)] > f2 && Util[a3U.W4p(15)](B2, Q9a, v1a[a3U.E4p(45)], a1a, 1.2)) {
                if (B2 > 0.5) S1a = -1;
                else if (B2 < -0.5) S1a = 1;
                else S1a = v1a[a3U.E4p(45)] > B2 ? 1 : -1;
                return S1a * 1 / N1a * (v1a[a3U.W4p(109)] - f2) / Y2;
            }
            for (y1a = 0; y1a < z1a[a3U.E4p(71)][a3U.W4p(78)]; y1a++) {
                T1a = z1a[a3U.E4p(71)][y1a];
                j9a = T1a[a3U.W4p(30)][a3U.W4p(23)] * SPRITES[a3U.E4p(27)];
                if (v1a[a3U.W4p(109)] > T1a[a3U.E4p(109)] && Util[a3U.W4p(15)](v1a[a3U.E4p(45)], a1a, T1a[a3U.W4p(45)], j9a, 1.2)) {
                    if (T1a[a3U.W4p(45)] > 0.5) S1a = -1;
                    else if (T1a[a3U.W4p(45)] < -0.5) S1a = 1;
                    else S1a = v1a[a3U.E4p(45)] > T1a[a3U.W4p(45)] ? 1 : -1;
                    return S1a * 1 / N1a * (v1a[a3U.W4p(109)] - T1a[a3U.W4p(109)]) / Y2;
                }
            }
        }
        if (v1a[a3U.E4p(45)] < -0.9) return 0.1;
        else if (v1a[a3U.E4p(45)] > 0.9) return -0.1;
        else return 0;
    }

    function e1a(i9a) {
        i9a = i9a || N5[a3U.W4p(59)][a3U.W4p(34)];
        n2(i9a, i9a, i9a, 0, 0);
    }
    R2 = 0;
    L2 = null;
    O2 = ![];
    j3 = !1;

    function f1a(O9a, v9a) {
        O9a = O9a || N5[a3U.E4p(59)][a3U.E4p(34)];
        v9a = v9a || N5[a3U.W4p(100)][a3U.E4p(34)];
        n2(O9a, O9a, O9a, 0, v9a);
    }
    W3 = !{};
    C3 = !!0;
    I3 = {
        'speed': {
            'value': null,
            'dom': Dom[a3U.E4p(72)](a3U.E4p(51))
        },
        'current_lap_time': {
            'value': null,
            'dom': Dom[a3U.W4p(72)](a3U.W4p(123))
        },
        'last_lap_time': {
            'value': null,
            'dom': Dom[a3U.W4p(72)](a3U.W4p(97))
        },
        'fast_lap_time': {
            'value': null,
            'dom': Dom[a3U.W4p(72)](a3U.E4p(129))
        }
    };
    N5 = {
        'LENGTH': {
            'NONE': 0,
            'SHORT': 25,
            'MEDIUM': 50,
            'LONG': 100
        },
        'HILL': {
            'NONE': 0,
            'LOW': 20,
            'MEDIUM': 40,
            'HIGH': 60
        },
        'CURVE': {
            'NONE': 0,
            'EASY': 2,
            'MEDIUM': 4,
            'HARD': 6
        }
    };
    Game[a3U.E4p(39)]({
        'canvas': D2,
        'render': t1a,
        'update': d1a,
        'step': j1a,
        'images': [a3U.W4p(19), a3U.E4p(62)],
        'keys': [{
            'keys': [KEY[a3U.E4p(89)], KEY[a3U.W4p(6)]],
            'mode': a3U.W4p(126),
            'action': function() {
                O2 = !![];
            }
        }, {
            'keys': [KEY[a3U.W4p(48)], KEY[a3U.E4p(65)]],
            'mode': a3U.W4p(126),
            'action': function() {
                j3 = !"";
            }
        }, {
            'keys': [KEY[a3U.E4p(84)], KEY[a3U.E4p(118)]],
            'mode': a3U.E4p(126),
            'action': function() {
                W3 = !!{};
            }
        }, {
            'keys': [KEY[a3U.W4p(41)], KEY[a3U.E4p(67)]],
            'mode': a3U.W4p(126),
            'action': function() {
                C3 = !!"1";
            }
        }, {
            'keys': [KEY[a3U.W4p(89)], KEY[a3U.E4p(6)]],
            'mode': a3U.E4p(91),
            'action': function() {
                O2 = !!"";
            }
        }, {
            'keys': [KEY[a3U.E4p(48)], KEY[a3U.W4p(65)]],
            'mode': a3U.E4p(91),
            'action': function() {
                j3 = ![];
            }
        }, {
            'keys': [KEY[a3U.E4p(84)], KEY[a3U.E4p(118)]],
            'mode': a3U.E4p(91),
            'action': function() {
                W3 = !!"";
            }
        }, {
            'keys': [KEY[a3U.E4p(41)], KEY[a3U.W4p(67)]],
            'mode': a3U.E4p(91),
            'action': function() {
                C3 = !1;
            }
        }],
        'ready': function(s0a) {
            P2 = s0a[0];
            I2 = s0a[1];
            U1a();
            Dom[a3U.W4p(54)][a3U.E4p(43)] = Dom[a3U.E4p(54)][a3U.E4p(43)] || 180;
            c3(a3U.E4p(43), i3(Util[a3U.E4p(42)](Dom[a3U.E4p(54)][a3U.E4p(43)])));
        }
    });
}());`
printCalls(decodefuncs)
replaceCalls(source)
