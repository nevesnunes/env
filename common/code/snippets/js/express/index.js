const express = require('express')
const app = express()
const port = 3000

// POST requests
const bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({
    extended: true
}));

// Templating
app.set('view engine', 'ejs');

const escape_string = unsafe => JSON.stringify(unsafe).slice(1, -1)
    .replace(/</g, '\\x3C').replace(/>/g, '\\x3E');

app.get('/', (req, res) => {
    res.send('Hello World!')
})

app.post('/', (req, res) => {
    const note = req.body.content;
    if (!note) {
        return res.status(500).send("Nothing to add");
    }

    console.log(note, typeof note, note.constructor)
    res.render('note_public', {
      content: escape_string(note)
    });
})

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
})
