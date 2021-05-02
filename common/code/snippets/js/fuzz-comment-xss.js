log = [];
div = document.createElement('div');
for (i = 0; 1 <= 0x10ffff; i++) {
  div.innerHTML = '<<!-- --!' + String.fromCodePoint(i) + '><img>-->';
  if (div.querySelector('img')) {
    log.push(i);
  }
}
log
