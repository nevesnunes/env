<?php 

    $fname = $argv[1];
    $im = imagecreatefrompng($fname);
    list($sx, $sy) = getimagesize($fname);
    
    # -----------------------------------------------------------
    # Divide the image into blocks and count a colors in each one
    # For each color calculate average count in one block
    # -----------------------------------------------------------
    $xblocks = 8;
    $yblocks = 8;
    $xsize = intval($sx/$xblocks);
    $ysize = intval($sy/$yblocks);
    $count = $avg_count = array();
    for ($yb = 0; $yb < $yblocks; $yb++) {
    for ($xb = 0; $xb < $xblocks; $xb++) {
        for ($y = $yb*$ysize; $y < ($yb+1)*$ysize; $y++) {
        for ($x = $xb*$xsize; $x < ($xb+1)*$xsize; $x++) {
            $c = imagecolorat($im, $x, $y);
            @$count[$yb][$xb][$c]++;
        }}
        foreach ($count[$yb][$xb] as $color => $color_count) {
            @$avg_count[$color] += $color_count/($xblocks*$yblocks);
        }
    }}

    # -----------------------------------------------------------
    # Calculate a dispersion (deviation) from average count
    # for each color as sum of each block's squared difference
    # -----------------------------------------------------------
    $d = array();
    $dmax = 0;
    for ($yb = 0; $yb < $yblocks; $yb++) {
    for ($xb = 0; $xb < $xblocks; $xb++) {
        foreach ($count[$yb][$xb] as $color => $color_count) {
            @$d[$color] += pow($color_count - $avg_count[$color], 2);
            if ($d[$color] > $dmax) $dmax = $d[$color];
        }
    }}
    
    # -----------------------------------------------------------
    # Calculate average dispersion, just for information
    # -----------------------------------------------------------
    $avg_d = 0;
    foreach ($d as $disp) {
        $avg_d += $disp;
    }
    $avg_d /= count($d);
    echo "MAX disp: ".round($dmax,2)."; AVG: ".round($avg_d,2)."\n";
    
    # -----------------------------------------------------------
    # Find the largest "gap" in array, use it as edge
    # -----------------------------------------------------------
    asort($d);
    $gap = 0;
    $gap_disp = 0;
    $prev_disp = -1;
    foreach ($d as $color=>$disp) {
        if ($prev_disp > 0) {
            if ($disp - $prev_disp > $gap) {
                $gap = $disp - $prev_disp;
                $gap_disp = $prev_disp + ($disp - $prev_disp)/2;
            }
        }
        $prev_disp = $disp;
    }
    echo "GAP: ".round($gap_disp,2)." ± ".round($gap/2,2)."\n";

    # -----------------------------------------------------------
    # Blacken pixels with disp < $limit
    # -----------------------------------------------------------
    $limit = $gap_disp; //we can use intval($dmax/3);
    for ($y = 0; $y < $sy; $y++) {
    for ($x = 0; $x < $sx; $x++) {
        $c = imagecolorat($im, $x, $y);
        if ($d[$c] < $limit) { 
            imagesetpixel($im, $x, $y, 0);
        }
    }}
    
    imagepng($im, "solve.png");
    echo "DONE.\n";
    
?>
