# frequency analysis

https://www.discogs.com/group/thread/725367#7201568

# Ripping

```bash
sg cdrom -c 'whipper cd rip --offset=6 --unknown --cdr'
```

# Edit mp3 without re-compression

```bash
ffmpeg -i foo.mp3 -ss 00:00:01.0 -t 00:05:00 -c copy bar.mp3
for i in *.mp3; do mp3gain -g 4.5 "$i"; done
for i in *.mp3; do mp3gain -u "$i"; done
```

# Copy stream without re-compression

```bash
ffmpeg -i "input.webm" -vn -acodec copy "output.oga"
```

# Remove tone, spectogram edit, notch filter

https://manual.audacityteam.org/man/spectral_selection.html

Audacity > Audio > Analyze menu > Plot spectrum
Audacity > Audio > Effect menu > Notch filter
Q=16.0

http://www.learningaboutelectronics.com/Articles/Quality-factor-calculator.php

Use higher resolution for FFT and check if this is 15625Hz or 15750Hz - if this is one of those two then it means that you have TV Horizontal deflection frequency (probably crosstalk from cabling or poor PCB layout) - small differences from nominal frequency usually mean sampling clock shift/drift.

There is one argument to remove such signal - this interferer stealing bits from useful signal so you can improve lossy coding by removing unwanted signal thus more bits will be allocated to useful signal (doubt about serious quality improvement but depend on codec and overall bitrate).

# peak db, max gain allowed without clipping

```bash
for i in *.flac; do ffmpeg -i "$i" -af "volumedetect" -vn -sn -dn -f null /dev/null; done 2>&1 | grep -o 'max_volume.*'
```

https://superuser.com/questions/323119/how-can-i-normalize-audio-using-ffmpeg

# click removal

Spectrogram view instead of looking at the waveform often makes this much easier. The clicks and pops show up as vertical lines.

In Adobe Audition you can just select the affected samples and use the auto-heal function and it will usually draw the waveform exactly as it should be. Alternatively you can select the general area of the click and use the declick filter with moderate settings and it will only zap the click, as long as it's not crossing over a transient (beginning of a percussion hit) or is in the middle of horns or dense sawtooth harmonics.

It helps a bit to have the data preferences set to crossfade all edits by 1 or 2 ms. You can also draw a box in the spectrogram to confine your edits to just a certain frequency range, which is useful if the usual methods can't quite nail a low-frequency pop without killing the higher frequencies too.

On rare occasion where there's a massive pop, I might do some trickery with inverting the pop in one channel, or copying and mix-pasting the other channel's audio in, just to get the waveform closer to correct, and then auto-heal that. I've also experimented with converting a particularly crackly area to mid-side stereo, then auto-declicking the side more aggressively than the mid before converting back...this also helps reduce some sibilant distortion as found in "inner groove" areas of well-worn records, although it's never perfect. 

Source: https://www.discogs.com/group/thread/725367#7201568
