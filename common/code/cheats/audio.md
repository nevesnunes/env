# Modify volume

```bash
pactl list sink-inputs  # Take $sink_input
pactl set-sink-input-mute "$sink_input" toggle
```

# Compare audio fingerprints

```bash
paste -d$'\t' \
    <(ls -1 ./foo/*.flac) \
    <(ls -1 ./bar/*.flac) \
    | while IFS=$'\t' read -r i j; do diff <(fpcalc "$i") <(fpcalc "$j"); done
```

# Compare frequencies

```bash
sox -S -m -v 1 foo.flac -v -1 bar.flac -n spectrogram -x 640 -y 200 -Z -30 -o diff.png
```

- https://stackoverflow.com/questions/60787686/ffmpeg-lowpass-filter-increase-roll-off

# Ripping

```bash
sg cdrom -c 'whipper cd rip --offset=6 --unknown --cdr'
```

### IDs

```bash
wine ~/opt/CUETools_2.1.6/ArCueDotNet.exe _ | grep ID
# - [CTDB TOCID: wAKna2rolwFEvESF8jrHmRdm1ZQ-] found.
#     - http://db.cuetools.net/?tocid=wAKna2rolwFEvESF8jrHmRdm1ZQ-
# - [AccurateRip ID: 001eb21b-015c3e09-ca0f7b0f] found.
#     - .cue DISCID = ca0f7b0f
```

Alternatives:

- Chromaprint
    - `beet import -C`
    - [Chromaprint/Acoustid Plugin &mdash; beets 1\.4\.9 documentation](https://beets.readthedocs.io/en/stable/plugins/chroma.html)
- [Look up musicbrainz disc id and freedb id from EAC/XLD log](http://eac-log-lookup.blogspot.com/)
    - [Lookup musicbrainz and freedb by EAC log · GitHub](https://gist.github.com/kolen/766668)
    - e.g. http://musicbrainz.org/cdtoc/attach?toc=1%2015%20...
- `dotnet tool install -g MetaBrainz.MusicBrainz.dotnet-mbdiscid`
    - `dotnet mbdiscid`
- [ISRC \- MusicBrainz](https://musicbrainz.org/doc/ISRC)

# id3

- Tags
    - `TXXX`: User Defined Text

# wavpack (wv)

```bash
# List tags
wvunpack -ss foo.wv
wvtag -l foo.wv

# Extract wav + cue
wvunpack -cc foo.wv
# Given zip with `.wv` extension: Extract files not listed in APEv2 tags
atool -x foo.wv

xxd -l80 foo.wv
# 00000000: 7776 706b a08c 0000 0604 0000 c868 ab08  wvpk.........h..
# 00000010: 0000 0000 44ac 0000 3118 bc04 68ba ac98  ....D...1...h...
# 00000020: 2116 5249 4646 44a3 ad22 5741 5645 666d  !.RIFFD.."WAVEfm
# 00000030: 7420 1000 0000 0100 0200 44ac 0000 10b1  t ........D.....
# 00000040: 0200 0400 1000 6461 7461 20a3 ad22 0205  ......data .."..
```

# mp3

```bash
# Encoder version
strings _ | grep -o 'LAME[0-9\.]\+' | sort | uniq -c
```

# Remove images without re-compression

```bash
eyeD3 --remove-all-images *.mp3
for i in *; do ffmpeg -i "$i" -map_metadata 0 -c:a copy -map 0:a "0.$i" && mv "0.$i" "$i"; done
```

# Edit duration without re-compression

```bash
ffmpeg -ss 00:00:01.5 -i foo.mp3 -t 00:05:00 -c copy bar.mp3
```

# Edit replay gain without re-compression

```bash
# Add
mp3gain -g 4.5 *.mp3
mp3gain -r **/*.mp3

# Use glob to calculate album gain
mp3gain -a *.mp3
metaflac --add-replay-gain *.flac

# Remove
mp3gain -u **/*.mp3
metaflac --remove-replay-gain *.flac
eyeD3 --user-text-frame="REPLAYGAIN_TRACK_GAIN:" *.mp3
```

# Convert flac to mp3

```bash
ffmpeg -i in.flac -ab 320k -map_metadata 0 -id3v2_version 3 out.mp3
```

# Re-compress flac

```bash
for i in ./*.flac; do ffmpeg -i "$i" -c:a flac -compression_level 12 "0.$i" && mv "0.$i" "$i"; done
```

# Copy stream without re-compression

```bash
ffmpeg -i "input.webm" -vn -acodec copy "output.oga"
```

# Generate blank video and audio

```bash
ffmpeg -f lavfi -i color=size=8x8:rate=25:color=black -f lavfi -i anullsrc=channel_layout=mono:sample_rate=8000 -t $((60 * 60 * 4)) output.mp4
```

# Generate silence

```bash
sox -n -r 16000 -c 1 out.ogg trim 0.0 0.1
```

# Generate spectrogram

```bash
sox _ -c2 -r 44100 -n spectrogram
```

# Generate noise

```bash
sox -n -t waveaudio -r 48000 synth pinknoise band -n 2500 6000 reverb 2 vol 0.5
sox -m \
    |sox -n -t waveaudio -r 50000 synth trapezium mix F2 band -n 8192 12000 vol 0.1 \
    |sox -n -t waveaudio -r 50000 synth trapezium mix G2 band -n 8192 12000 pitch 50 vol 0.1 \
    |sox -n -t waveaudio -r 50000 synth pinknoise band -n 2500 6000 reverb 2 vol 0.5
```

# Remove tone, spectogram edit, notch filter

- https://manual.audacityteam.org/man/spectral_selection.html
    - Audacity > Audio > Analyze menu > Plot spectrum
    - Audacity > Audio > Effect menu > Notch filter
    - Q=16.0

- http://www.learningaboutelectronics.com/Articles/Quality-factor-calculator.php

> Use higher resolution for FFT and check if this is 15625Hz or 15750Hz - if this is one of those two then it means that you have TV Horizontal deflection frequency (probably crosstalk from cabling or poor PCB layout) - small differences from nominal frequency usually mean sampling clock shift/drift.
> There is one argument to remove such signal - this interferer stealing bits from useful signal so you can improve lossy coding by removing unwanted signal thus more bits will be allocated to useful signal (doubt about serious quality improvement but depend on codec and overall bitrate).

# peak db, max gain allowed without clipping

```bash
for i in *.flac; do ffmpeg -i "$i" -af "volumedetect" -vn -sn -dn -f null /dev/null; done 2>&1 | grep -o 'max_volume.*'
```

- https://superuser.com/questions/323119/how-can-i-normalize-audio-using-ffmpeg

# click removal

> Spectrogram view instead of looking at the waveform often makes this much easier. The clicks and pops show up as vertical lines.
> In Adobe Audition you can just select the affected samples and use the auto-heal function and it will usually draw the waveform exactly as it should be. Alternatively you can select the general area of the click and use the declick filter with moderate settings and it will only zap the click, as long as it's not crossing over a transient (beginning of a percussion hit) or is in the middle of horns or dense sawtooth harmonics.
> It helps a bit to have the data preferences set to crossfade all edits by 1 or 2 ms. You can also draw a box in the spectrogram to confine your edits to just a certain frequency range, which is useful if the usual methods can't quite nail a low-frequency pop without killing the higher frequencies too.
> On rare occasion where there's a massive pop, I might do some trickery with inverting the pop in one channel, or copying and mix-pasting the other channel's audio in, just to get the waveform closer to correct, and then auto-heal that. I've also experimented with converting a particularly crackly area to mid-side stereo, then auto-declicking the side more aggressively than the mid before converting back...this also helps reduce some sibilant distortion as found in "inner groove" areas of well-worn records, although it's never perfect.
    - [Discogs Groups - Manual Click Removal Method, for those whose use the pencil](https://www.discogs.com/group/thread/725367#7201568)

# dynamic range

> The 16-bit compact disc has a theoretical undithered dynamic range of about 96 dB; however, the perceived dynamic range of 16-bit audio can be 120 dB or more with noise-shaped dither, taking advantage of the frequency response of the human ear.
    - https://en.wikipedia.org/wiki/Dynamic_range
    - => Dithering noise should be above noise floor (-96 dB)

# modulation

- https://medium.com/poka-techblog/back-to-basics-decoding-audio-modems-with-audacity-c94faa8362a0
    - ~/Downloads/Back to basics_ Decoding Audio Modems with Audacity _ by Maxime Leblanc _ poka-techblog _ Medium (09_05_2021 15_32_46).html
