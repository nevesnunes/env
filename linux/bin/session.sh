#!/bin/perl
#
# >session save
# >session restore [0-2]
#
# 0: Restore geometries of existing windows
# 1: Restore geometries of matching windows
# 2: Restore geometries of missing windows

my %exceptions = (
  # Exceptions for applications that manage their own windows:
  self_managed => [
    'Navigator.Firefox',
    'QVCLSalFrame.libreoffice-',
    'Pidgin.Pidgin', 'skype.Skype',
  ],
  # Exceptions for non-application windows:
  non_applications => [
    'file_progress.Nautilus',
  ],
  # Special handling of tray applications if xdotool is available:
  tray_applications => [
    'pidgin',
    'skype',
  ],
);

# Does SIGPWR trigger saving cookie state?
# Save multiple states...
#   Detect reboot...
# Handle minimized state; for Pidgin and Skype too...
# What happens when there aren't enough desktops? (after reboot)
# VLC full-screen is different from WM full-screen
# Handle _NET_WM_STATE_DEMANDS_ATTENTION (new nautilus window)
# Detect open documents...?
# $level=2: Command may error (eg, if file is missing)
#   Perhaps shorten wait by tracking $pid's to detect failure?
# Zenity interface if display is available?

die "ERROR: Must not run as root.\n" if $< eq ( getpwnam ( "root" ) )[2];
die "ERROR: wmctrl is not available.\n"
  if system ( "which wmctrl >/dev/null 2>&1" );

use Data::Dumper;

my $session = "$ENV{HOME}/.config/gnome-session/saved-session/session.ini";
my $action = $ARGV[0];

if ( ! exists ( $ENV{DISPLAY} ) )
{
  open ( my $W, "w -hsf $ENV{USER}|" );
  while ( <$W> )
  {
    if ( /^$ENV{USER}\s+(:\d+)\s+/ )
    {
      $ENV{DISPLAY} = $1;
      last;
    }
  }
  close ( $W );

  die "ERROR: DISPLAY not set.\n" if ! exists ( $ENV{DISPLAY} );
}

my $windows = {};
wmctrl ( $windows );

if    ( $action eq "save" )
{
  require File::Basename;
  require File::Path;
  File::Path::mkpath ( File::Basename::dirname ( $session ) )
    if ! -d "" . File::Basename::dirname ( $session );

  open ( my $SES, ">$session" );
  print $SES Data::Dumper->Dump ( [ $windows ], [ '$windows' ] );
  close ( $SES );

  print "Session saved.\n";
}
elsif ( $action eq "restore" )
{
  my $windows_cur = $windows;
  {
    open ( my $SES, "<$session" ) || die ( "No saved session.\n" );
    local $/ = undef;
    $windows = <$SES>;
    eval ( $windows );
  }

  print "Restoring session.\n";
  my $level = $ARGV[1];

  if ( $level > 0 )
  {
    my %windows = %$windows; my %windows_cur = %$windows_cur;

    # Matching IDs:

    foreach my $id ( keys ( %windows ) )
    {
      if ( exists ( $windows_cur->{$id} ) and
           $windows->{$id}->{pid} eq $windows_cur->{$id}->{pid} and
           $windows->{$id}->{class} eq $windows_cur->{$id}->{class} and
           $windows->{$id}->{command} eq $windows_cur->{$id}->{command} )
      {
        delete ( $windows{$id} );
        delete ( $windows_cur{$id} );
      }
      else
      {
        delete ( $windows->{$id}->{id} );
        delete ( $windows->{$id}->{pid} );
      }
    }

    # Matching properties:

    foreach my $prop ( "name", "command", "class" )
    {
      foreach my $wid ( keys ( %windows ) )
      {
        foreach my $cid ( keys ( %windows_cur ) )
        {
          if ( $windows->{$wid}->{$prop} eq $windows_cur->{$cid}->{$prop} )
          {
            $windows->{$wid}->{id} = $cid;
            $windows->{$wid}->{pid} = $windows_cur->{$cid}->{pid};
            delete ( $windows{$wid} );
            delete ( $windows_cur{$cid} );
            last;
          }
        }
      }
    }

    # Run commands:

    if ( $level > 1 )
    {
WINDOW:
      foreach my $id ( keys ( %windows ) )
      {
        foreach my $class ( @{$exceptions{non_applications}} )
        {
          if ( $windows->{$id}->{class} =~ /^\Q$class\E/ )
          {
            delete ( $windows{$id} );
            next WINDOW;
          }
        }

        foreach my $class ( @{$exceptions{self_managed}} )
        {
          if ( $windows->{$id}->{class} =~ /^\Q$class\E/ )
          {
            if ( grep { $_->{class} =~ /^\Q$class\E/ }
                      ( values ( %$windows_cur ) ) )
            {
              delete ( $windows{$id} );
              next WINDOW;
            }
            $windows_cur->{$class}->{class} = $class;
          }
        }

        print "DEBUG: $windows->{$id}->{command} ($id)"
              . " - restore missing window...\n";
        my $pid = fork();
        if ( ! $pid )
        {
          open ( STDERR, '>>', "$ENV{HOME}/.xsession-errors" ) || die;
          exec ( split ( /\0/, $windows->{$id}->{command} ) ) || die;
        }
        $windows->{$id}->{pid} = $pid;
      }

      %windows_cur = (); my $sleep = 0;
      while ( scalar ( keys ( %windows ) ) )
      {
        last if $sleep++ > 10; sleep ( 1 ); print ".";
        %windows_cur = ( %windows_cur, wmctrl ( $windows_cur ) );
        next if ! scalar ( keys ( %windows_cur ) );

        foreach my $prop ( "name", "command", "class" )
        {
          foreach my $wid ( keys ( %windows ) )
          {
            foreach my $cid ( keys ( %windows_cur ) )
            {
              if ( $windows->{$wid}->{$prop} eq $windows_cur->{$cid}->{$prop} )
              {
                $windows->{$wid}->{id} = $cid;
                $windows->{$wid}->{pid} = $windows_cur->{$cid}->{pid};
                delete ( $windows{$wid} );
                delete ( $windows_cur{$cid} );
                last;
              }
            }
          }
        }
      }

      print "\n" if $sleep;
    }
  }

  # Restore window properties:

  my $focus = undef;
  foreach my $id ( keys ( %$windows ) )
  {
    next if ! exists ( $windows->{$id}->{workspace} );

    my $session = $windows->{$id};
    my $current = $windows_cur->{ $session->{id} };

    if ( defined ( $current ) and $session->{class} eq $current->{class} and
                                  $session->{command} eq $current->{command} )
    {
      if ( $session->{workspace} ne $current->{workspace} )
      {
        print "DEBUG: $session->{command} ($current->{id})"
              . " - move workspace from $current->{workspace}"
                                 . " => $session->{workspace}\n";
        system ( "wmctrl -ir $current->{id} -t $session->{workspace}" );
      }

      if ( ( $session->{state}->{"_NET_WM_STATE_MAXIMIZED_VERT"} or
             $session->{state}->{"_NET_WM_STATE_MAXIMIZED_HORZ"} ) and
           $session->{_geometry} ne $current->{_geometry} )
      {
        print "DEBUG: $session->{command} ($current->{id})"
              . " - switch from $current->{geometry}"
                         . " => $session->{geometry}\n";
        system ( "wmctrl -ir $current->{id} -b toggle,maximized_horz" )
          if delete ( $current->{state}->{"_NET_WM_STATE_MAXIMIZED_HORZ"} );
        system ( "wmctrl -ir $current->{id} -b toggle,maximized_vert" )
          if delete ( $current->{state}->{"_NET_WM_STATE_MAXIMIZED_VERT"} );
        system ( "wmctrl -ir $current->{id} -e $session->{geometry}" );
        $current->{_geometry} = $session->{_geometry};
      }

      foreach my $prop ( keys ( %{$session->{state}} ),
                         keys ( %{$current->{state}} ) )
      {
        if    ( $prop eq "_NET_WM_STATE_FOCUSED" )
        {
          $focus = "wmctrl -ia $current->{id}";
        }
        elsif ( $session->{state}->{$prop} ne $current->{state}->{$prop} )
        {
          print "DEBUG: $session->{command} ($current->{id})"
                . " - toggle property $prop\n";
          $prop = { "_NET_WM_STATE_MAXIMIZED_VERT" => "wmctrl -ir $current->{id} -b toggle,maximized_vert",
                    "_NET_WM_STATE_MAXIMIZED_HORZ" => "wmctrl -ir $current->{id} -b toggle,maximized_horz",
#                    "_NET_WM_STATE_HIDDEN" => "xdotool windowminimize",
#                    "_NET_WM_STATE_DEMANDS_ATTENTION" => "xdotool ???",
                    "_NET_WM_STATE_FULLSCREEN" => "wmctrl -ir $current->{id} -b toggle,fullscreen" }->{$prop};
          system ( $prop ) if $prop;
        }
      }

      if ( $session->{_geometry} ne $current->{_geometry} )
      {
        print "DEBUG: $session->{command} ($current->{id})"
              . " - move from $current->{geometry}"
                       . " => $session->{geometry}\n";
        system ( "wmctrl -ir $current->{id} -e $session->{geometry}" );
      }
    }
  }

  system ( $focus ) if $focus;
}
else
{
  die ( "Usage: session save\n"
      . "       session restore [0-2]\n" );
}

# Get current window list from wmctrl
sub wmctrl
{
  my $windows = shift; my %windows = ();

  open ( my $WIN, "wmctrl -lpGx|" );
  while ( <$WIN> )
  {
    chop;

    my %window = ();
    ( $window{id}, $window{workspace}, $window{pid},
      $window{offset_x}, $window{offset_y}, $window{size_x}, $window{size_y},
      $window{class} ) = split ( /\s+/ );
    next if exists ( $windows->{$window{id}} );
    ( $window{name} ) = ( /^(?:\S+\s+){8}(.+)$/ );

    $window{_geometry} = join ( ",", int($window{offset_x}/20+.5),
                                     int($window{offset_y}/20+.5),
                                     int($window{size_x}/20+.5),
                                     int($window{size_y}/20+.5) );
    $window{geometry} = join ( ",", 10, delete ( $window{offset_x} ),
                                        delete ( $window{offset_y} ) - 40,
                                        delete ( $window{size_x} ),
                                        delete ( $window{size_y} ) );
    $window{command} = substr ( `cat /proc/$window{pid}/cmdline`, 0, -1 );
    $window{_state} = ( split ( " = ", substr ( `xprop -id $window{id} _NET_WM_STATE`, 0, -1 ) ) )[1];
    foreach my $prop ( split ( /\s*,\s*/, delete ( $window{_state} ) ) )
      { $window{state}{$prop}++; }

    $windows{$window{id}} = $windows->{$window{id}} = \%window;
  }
  close ( $WIN );

  if ( ! system ( "which xdotool >/dev/null 2>&1" ) )
  {
    my %class = ();
    my $temp = '^' . join ( '$|^', @{$exceptions{tray_applications}} ) . '$';
    foreach my $id ( `xdotool search --any --classname '$temp'` )
    {
      chop;

      my %window = (); my %xprop = ();
      $window{id} = "0x" . lc ( sprintf ( "%08x", $id ) );
      open ( my $WIN, "xprop -id $window{id} -notype"
                      . " WM_CLASS WM_NAME _NET_WM_PID|" );
      while ( <$WIN> )
      {
        chop;
        $xprop{$1} = $2 if /^(\w+)\s+=\s+(\S.*)$/;
      }
      close ( $WIN );

      if ( ! $class{$xprop{'WM_CLASS'}}++ )
      {
        $window{pid} = $xprop{'_NET_WM_PID'};
        $window{class} = join ( ".", split ( '", "', $xprop{'WM_CLASS'} ) );
        $window{class} =~ s/^"|"$/usr/g;
        $window{name} = $xprop{'WM_NAME'};
        $window{command} = substr ( `cat /proc/$window{pid}/cmdline`, 0, -1 );

        $windows{$window{id}} = $windows->{$window{id}} = \%window;
      }
    }
  }

  return ( %windows );
}
