# 1) to save all frames from (-i INPUT_VIDEO) input video file,
# (-ss 00:10:00) started at 10 minute and (-t 10) stop after 10 seconds,
# (-same_quant) use same quantizer as source (-f image2) with image2 muxer and
# (img-%04d.jpg) img-0001.jpg pattern
#
# - you get bunch of files

ffmpeg -i INPUT_VIDEO -ss 00:10:00 -t 10 -same_quant -f image2 img-%04d.jpg

# 2) to save (-r 6) 6 frames in second
# 
# - if input file have 24 FPS and you set output to 6
# - you get 1/4 of all frames

ffmpeg -i INPUT_VIDEO -ss 00:10:00 -t 10 -same_quant -r 6 -f image2 img-%04d.jpg

# 3) to save only I-frames ( -vsync 0 -vf select='eq(pict_type\,I)' )
#
# - you get few files

ffmpeg -i INPUT_VIDEO -vsync 0 -vf select='eq(pict_type\,I)' -ss 00:11:00 -t 60 -same_quant -f image2 img-%04d.jpg

# 4) to save only P-frames
# - you get about half of full numbers of files, its depend on original coding settings

ffmpeg -i INPUT_VIDEO -vsync 0 -vf select='eq(pict_type\,P)' -ss 00:11:00 -t 60 -same_quant -f image2 img-%04d.jpg