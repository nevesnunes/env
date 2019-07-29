function xrandr_reset_4m {
  # DVI-I-1 DP-1  VGA1
  #         HDMI1
  BOTTOM='HDMI-1'
  MIDDLE='DP-2'
  LEFT='DVI-I-1'
  RIGHT='VGA-1'
  xrandr --output $BOTTOM --rotate inverted
  xrandr --output $BOTTOM --primary
  xrandr --output $BOTTOM --below $MIDDLE
  xrandr --output $RIGHT --right-of $MIDDLE
  xrandr --output $LEFT --left-of $MIDDLE
}

# Note 1: Firstly do a query on the connected port (ie projector)
xrandr --query


# Note 2: Setting the best resolution for the connected port (ie projector)
xrandr --output VGA --auto


# Note 3: Cloning mode for both internal monitor (DVI) and external projector (VGA)
xrandr --output VGA --mode 1024x768 --same-as DVI --output DVI --mode 1024x768


# Note 4: Switching Off the Video Projector and turn off the Internal Monitor
xrandr --output VGA --off
xrandr --output DVI --auto
