# Record screen
ffmpeg -i input -c:v libx264 -preset ultrafast -qp 0 output.mkv

# Record screen with sound
ffmpeg -f alsa -i pulse -c:v libx264 -preset ultrafast -qp 0 output.mkv

# Record part of screen
ffmpeg -f x11grab -r 25 -s 1280x720 -i :0.0+0,24 -vcodec libx264 -preset ultrafast video.mkv

# Convert to webm
ffmpeg -threads 4 -i ~/tmp/grab.mkv -crf 10 -b:v 3M ~/tmp/grab.webm

# Lossless rotate
# add -noautorotate to ignore rotate metadata
ffmpeg -i in.mov -c:a copy -c:v libx264 -preset veryslow -qp 0 -vf "transpose=1" out.mov
