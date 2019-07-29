<?php
  ob_start();

  print_r("REQUEST FROM:\n".$_SERVER['REMOTE_ADDR']."\n");
  print_r("GET:\n".var_export($_GET, true)."\n");
  print_r("POST:\n".var_export($_POST, true)."\n");
  print_r("COOKIE:\n".var_export($_COOKIE, true)."\n");
  print_r("SERVER:\n".var_export($_SERVER, true)."\n\n");

  $result = ob_get_clean();

  file_put_contents ("out.xss", $result."\n\n");
?>
