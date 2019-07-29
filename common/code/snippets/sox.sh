# mains' hum
play -r 50000 -n -c2 \
       synth trapezium mix F2 band -n 8192 12000 \
       synth trapezium mix G2 band -n 8192 12000 pitch 50 \
       synth pinknoise mix band -n 2500 6000 reverb 20 \
       vol 2

# hand dryer
play -n -c2 \
       synth pinknoise band -n 2500 6000 reverb 2 \
       vol 2

# air conditioner
play -n -n --combine merge synth pinknoise band -n 1200 1800 tremolo 20 1 tremolo 0.14 2 tremolo 0.2 5

# beach waves
play -n -n --combine merge synth pinknoise band -n 1200 1800 tremolo 50 10 tremolo 0.14 70 tremolo 0.2 50

# noisier beach waves
play -n -c2 \
      synth brownnoise synth pinknoise mix \
      synth sine amod 0.1 75
