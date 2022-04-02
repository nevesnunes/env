# webcam workarounds

# if: uvcvideo 1-1.3:1.3: Failed to submit URB 0 (-28).
# then: not enough bandwidth, try USB 3.0 hub
dmesg
# https://community.jitsi.org/t/old-webcams-in-linux-gspca-drivers/38033
env LD_PRELOAD=/usr/lib64/libv4l/v4l1compat.so

# change fps

ffmpeg -i input.mp4 -c:v libx265 -crf 26 -preset fast -filter:v fps=30 output.mp4

# dump encrypted vobs
# See: https://www.reddit.com/r/linuxquestions/comments/5r0159/how_can_i_backup_copy_protected_dvds_on_linux/

sudo mount /dev/cdrom ~/tmp/cdrom
cd ~/tmp/cdrom
vobcopy --mirror -v -v -o ~/tmp/out
# ||
vlc dvd:/dev/dvd@1 --sout "#standard{access=file,mux=ps,dst=/home/user/file.ps}"
# ||
mplayer dvd://1 -dumpstream -dumpfile dump.vob

### debian

# On /etc/apt/sources.list:
# ```
# deb http://download.videolan.org/pub/debian/stable/ /
# ```
wget -O - https://download.videolan.org/pub/debian/videolan-apt.asc | apt-key add -
apt-get update
apt-get install libdvdcss2

# References:
# - https://www.rigacci.org/wiki/doku.php/doc/appunti/linux/video/vobcopy

# stream

mount -t UDF /dev/dvd /media/

ssh -XC4c arcfour,blowfish-cbc user@example.org mplayer ~/movie.mp4

dvd://1-123
sftp://
nfs

mpv dvd:// --alang=jpn,en --slang=en
mpv -playlist http://1.2.3.4/dvd/VIDEO_TS/playlist.m3u

# https://serverfault.com/questions/288137/how-to-stream-live-video-from-a-linux-server

vlc v4l:// :v4l-vdev="/dev/video0" :v4l-adev="/dev/audio2" --sout '#transcode{vcodec=FLV1,vb=512,acodec=mpga,ab=64,samplerate=44100}:std{access=http{mime=video/x-flv},mux=ffmpeg{mux=flv},dst=0.0.0.0:8081/stream.flv}'
vlc http://localhost:8081/stream.flv --sout '#std{access=http{mime=video/x-flv},mux=ffmpeg{mux=flv},dst=0.0.0.0:8082/stream.flv}'
vlc http://server_ip_address:8082/stream.flv

# rip dvd

ffmpeg -i concat:VTS_02_1.VOB\|VTS_02_2.VOB\|VTS_02_3.VOB\|VTS_02_4.VOB\|VTS_02_5.VOB -map 0:v:0 -map 0:a:0 -codec:a libvo_aacenc -ab 128 -codec:v libx264 -vpre libx264-ipod640 movie.mp4

# ||
ffmpeg -i your_VOB_file.VOB -c:v copy -c:a copy output.mp4

# ||
ffmpeg -analyzeduration 100M -probesize 100M -i output.vob
# Input #0, mpeg, from 'output.vob':
# Duration: 01:50:40.99, start: 0.287267, bitrate: 7581 kb/s
# Stream #0:0[0x1bf]: Data: dvd_nav_packet
# Stream #0:1[0x1e0]: Video: mpeg2video (Main), yuv420p(tv, top first), 720x576 [SAR 64:45 DAR 16:9], 25 fps, 25 tbr, 90k tbn, 50 tbc
# Stream #0:2[0x80]: Audio: ac3, 48000 Hz, 5.1(side), fltp, 384 kb/s
# Stream #0:3[0x89]: Audio: dts (DTS), 48000 Hz, 5.1(side), fltp, 768 kb/s
# Stream #0:4[0x82]: Audio: ac3, 48000 Hz, 5.1(side), fltp, 384 kb/s
# Stream #0:5[0x21]: Subtitle: dvd_subtitle
# Stream #0:6[0x20]: Subtitle: dvd_subtitle

ffmpeg \
  -analyzeduration 100M -probesize 100M \
  -i output.vob \
  -map 0:1 -map 0:3 -map 0:4 -map 0:5 -map 0:6 \
  -metadata:s:a:0 language=ita -metadata:s:a:0 title="Italian stereo" \
  -metadata:s:a:1 language=eng -metadata:s:a:1 title="English stereo" \
  -metadata:s:s:0 language=ita -metadata:s:s:0 title="Italian" \
  -metadata:s:s:1 language=eng -metadata:s:s:1 title="English" \
  -codec:v libx264 -crf 21 \
  -codec:a libmp3lame -qscale:a 2 \
  -codec:s copy \
  output.mkv

# ||
# Lossless rip
ffmpeg \
  -analyzeduration 100M -probesize 100M \
  -i output.vob \
  -map 0:v \
  -map 0:a \
  -map_metadata 0 \
  -map_metadata:s:v 0:s:v \
  -map_metadata:s:a 0:s:a \
  output.mkv

# Edit duration (copy) without speciying keyframes

ffmpeg -t 00:00:07.5 -i foo.mkv -ss 00:00:01 -c:v libx265 -x265-params lossless=1 bar.mkv

# Reencode lossless

ffmpeg -i foo.mkv -c:v libx264 -preset ultrafast -crf 0 bar.mkv
# || keyframe interval set to 5 seconds, given fps = 24
ffmpeg -i foo.mkv -c:v libx264 -x264-params keyint=$((5*24)):scenecut=0 -preset ultrafast -crf 0 bar.mkv
# ||
ffmpeg -i foo.mkv -c:v libx265 -x265-params lossless=1 bar.mkv
# ||
ffmpeg -i foo.mkv -c:v ffv1 bar.mkv

# Crop
# - Parameter: crop=$w:$h:$x:$y
# - Variables: in_w,in_h
# - Usage: -vf "crop=480:270:200:100"

# Noise
# Reference: https://stackoverflow.com/questions/15792105/simulating-tv-noise
# FIXME: Stops after a while
ffmpeg \
  -f rawvideo -video_size 1366x768 -pixel_format yuv420p -framerate 60 \
  -i /dev/urandom -bufsize 1920k -an -t 5 -vf hue=s=0 -f matroska \
  - | ffplay -
