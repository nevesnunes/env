# Audio

# Convert source to flac 16bits:22khz
for i in *.wav; do ffmpeg -i "$i" -af aformat=s16:44100 "${i%.*}".flac; done

# Copy metadata of specific stream
ffmpeg -i _ -map_metadata 0 -map 0:a -c:a copy _
for i in *.wav; do ffmpeg -i "$i" -map_metadata 0 -map 0:a -af aformat=s16:44100 "${i%.*}".flac; done

# Transform metadata tags
# -- https://unix.stackexchange.com/questions/250130/copy-file-creation-date-to-metadata-in-ffmpeg/492338#492338
exiftool -tagsFromFile inputfile.mov -all:all>all:all outputfile.mp4

# increase volume
for i in *.flac; do ffmpeg -i "$i" -filter:a "volume=6.5dB,aformat=s16:44100" "${i%.*}".v.flac </dev/null; done

# ---

# Video, 4K/UltraHD

# Crop Real 4K to UltraHD 4096>3840
ffmpeg -i A001_C014_01217G.4k.y4m -vf "crop=3840:2160:128:0" outputgirl.2160p.y4m

# Resize to 1080p
ffmpeg -i outputgirl.2160p.y4m -vf scale=1920:-1 outputgirl.1080p.y4m

# Resize to 720p
ffmpeg -i outputgirl.2160p.y4m -vf scale=1280:-1 outputgirl.720p.y4m

# Convert source to YUU4MPEG2
ffmpeg -pix_fmt yuv420p -i any-source-video.webm output.y4m

# Convert a sequence of images to YUU4MPEG
ffmpeg -f image2 -i "A004_C001_0122K7.00%05d.png" -pix_fmt yuv420p ouput.y4m

# cut without reencoding
ffmpeg -i input.mp4 -c copy -ss 00:01:00.000 -t 00:00:10.000 output.mp4

# extract a single frame
ffmpeg -i input.avi -f image2 -ss 14.342 -vframes 1 frame.png

# extract a single frame (altenative method)
ffmpeg -i input.y4m -f image2 -vf select="gte(n\, 1)" -vframes 1 frame.png

# extract 1 frame after frame 100
ffmpeg -i input.y4m -f image2 -vf select="gte(n\, 100)" -vframes 1 frame.png

# export subtitles

ffmpeg -i input.mkv -vn -an -codec:s:0.7 ass output_subtitle.ass
ffmpeg -i input.mkv -vn -an -codec:s:0.7 srt output_subtitle.srt

# troubleshooting

ffprobe -prefix -unit -pretty -show_streams -i  _ | vim -
ffmpeg -filters | vim -

-fflags +genpts -analyzeduration 1000M -probesize 1000M -i ...
-max_muxing_queue_size 9999
-threads 2
copy stream

# ---

# +

# -t 10 = 10 second
# scale=1920:-2:flags=lanczos <= yuv420p

i=foo && ext="${i##*.}" && ffmpeg -i "$i" -vf scale=1920:-1 -c:v libx264 -crf 18 -preset slow -c:a copy -map 0 "${i%.*}.1080p.$ext"

ffmpeg -y -i input4K.m2ts -c:v libx264 -pix_fmt yuv420p -preset slow -crf 18 -x264-params me=umh:merange=24:trellis=1:level=4.1:ref=5 -filter:v "crop=3840:1600:0:280, scale=1920:800" -an "1080_"$output.mkv

ffmpeg.exe -hwaccel dxva2 -ss 00:05:00.000 -i Sample.mkv -c:a copy -c:v libx265 -preset medium -crf 12 -tag:v hvc1 -pix_fmt yuv420p10le -x265-params "colorprim=bt2020:transfer=smpte2084:colormatrix=bt2020nc" -t 00:02:0.000 Sample.mp4

# https://ffmpeg.org/ffmpeg-filters.html#colorspace
# https://forum.doom9.org/showthread.php?t=175260

-c:v libx265 -tag:v hvc1 -crf 15 -pix_fmt yuv420p10le -x265-params "colorprim=bt2020:transfer=smpte2084:colormatrix=bt2020nc"

"colorprim=bt2020:transfer=smpte2084:colormatrix=bt2020nc:master-display=G(13250,34500)B(7500,3000)R(34000,16000)WP(15635,16450)L(10000000,10)"
and may be ':max-cll=0,0'

# hdr to sdr
# https://stevens.li/guides/video/converting-hdr-to-sdr-with-ffmpeg/
# https://ffmpeg.org/ffmpeg-filters.html#colorspace

ffplay -vf colorspace=iall=bt2020:all=bt709 _
ffplay -vf colorspace=space=bt709:primaries=bt2020 _
ffplay -vf colorspace=all=bt2020:range=tv:format=yuv420p10 _

ffmpeg -analyzeduration 10M -probesize 10M -i Exodus_UHD_HDR_Exodus_draft.mp4 -map 0:v:0 -map 0:a:0 -aspect 16:9 -pix_fmt yuv420p -vf scale=2560:1440:in_color_matrix=bt2020,format=rgb48,lut3d=bt2020_to_bt709_example.cube,scale=-1:-1:out_color_matrix=bt709 -c:v libx264 -preset fast -profile:v high -crf 18 -ac 2 -c:a aac -b:a 128k -y exodus-1440p-sdr-lut.mp4
ffmpeg -analyzeduration 10M -probesize 10M -i Exodus_UHD_HDR_Exodus_draft.mp4 -map 0:v:0 -map 0:a:0 -aspect 16:9 -vf scale=2560:1440,zscale=t=linear:npl=100,format=gbrpf32le,zscale=p=bt709,tonemap=tonemap=hable:desat=0,zscale=t=bt709:m=bt709:r=tv,format=yuv420p -c:v libx264 -preset fast -profile:v high -crf 18 -c:a aac -b:a 192k -y exodus-1440p-sdr-zscale.mp4

# parts

ffmpeg -i recording.mp4 -c copy -flags +global_header -segment_time n -f segment file%03d.mp4
ffmpeg -i file001.mp4 -{filter/encoding parameters} -fflags +genpts file001-new.mp4
```parts.txt
file 'file000-new.mp4'
file 'file001-new.mp4'
... 
file 'filelast-new.mp4'
```
ffmpeg -f concat -i parts.txt -c copy -fflags +genpts recording-encoded.mp4

# record

# -- https://trac.ffmpeg.org/wiki/Capture/Desktop
# -- http://ffmpeg.org/ffmpeg-devices.html#gdigrab
ffmpeg -f gdigrab -show_region 1 -framerate 6 -video_size cif -offset_x 10 -offset_y 20 -i desktop out.mpg

# convert to gif

# -- https://superuser.com/questions/556029/how-do-i-convert-a-video-to-gif-using-ffmpeg-with-reasonable-quality
# For web: fps=50
# -- https://wunkolo.tumblr.com/post/160942515402
ffmpeg -ss 30 -t 3 -i input.mp4 -vf "fps=50,scale=320:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" -loop 0 output.gif


