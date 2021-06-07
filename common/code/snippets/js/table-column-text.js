Array.prototype.slice.call(document.querySelectorAll("table.wikitable:nth-child(15) td:nth-child(3)")).map(e => e.innerText).filter(e => !/(N\/A)|(\(none\))/.test(e)).join(" ")
