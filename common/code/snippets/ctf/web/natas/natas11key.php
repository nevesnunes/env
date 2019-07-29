<?php
$orig_cookie = base64_decode('ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw');  
function xor_encrypt($in) {  
    $text = $in;  
    $key = json_encode(array( "showpassword"=>"no", "bgcolor"=>"#ffffff"));  
    $outText = '';  
    // Iterate through each character  
    for($i=0;$i<strlen($text);$i++) {  
        $outText .= $text[$i] ^ $key[$i % strlen($key)];  
    }  
    return $outText;  
}  
print xor_encrypt($orig_cookie);
?>  
