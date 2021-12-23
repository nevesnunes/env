-- Enable debug_print() output:
-- devilspie2 --debug

-- Invoke external script:
-- os.execute(os.getenv("HOME").."/bin/script.sh")

-- References:
-- [Allow reading of XA_WINDOW properties](http://git.savannah.gnu.org/cgit/devilspie2.git/commit/?id=6eb874931371b260e80cbc00e15cc895bc582ff5)
-- http://git.savannah.gnu.org/cgit/devilspie2.git/tree/src/xutils.h
-- http://git.savannah.gnu.org/cgit/devilspie2.git/tree/src/script_functions.h

function size_window (xid, operation)
    os.execute(os.getenv("HOME").."/bin/xsize.sh --id "..xid.." "..operation)
end
function move_window (xid, workspace)
    os.execute("wmctrl -i -r "..xid.." -t "..workspace)
end

-- Reference: https://specifications.freedesktop.org/wm-spec/1.3/ar01s05.html
transient = get_window_property('WM_TRANSIENT_FOR')
n = string.gsub(string.lower(get_window_name()), "%s+", "")
t = string.upper(get_window_type())
if (transient ~= '' or
        string.match(n, "scratchpad") or
        string.match(t, "WINDOW_TYPE_DESKTOP") or
        string.match(t, "WINDOW_TYPE_DIALOG") or
        string.match(t, "WINDOW_TYPE_DOCK") or
        string.match(t, "WINDOW_TYPE_MENU") or
        string.match(t, "WINDOW_TYPE_TOOLBAR") or
        string.match(t, "WINDOW_TYPE_UTILITY") or
        string.match(t, "WINDOW_TYPE_SPLASH") or
        string.match(t, "WINDOW_TYPE_SPLASHSCREEN")) then
    return
end

class = string.gsub(string.lower(get_window_class()), "%s+", "")
xid = get_window_xid()
x,y,w,h = get_window_geometry()
xs,ys = get_screen_geometry()
debug_print("get_window_name: "..n..
    "\nget_application_name: "..get_application_name()..
    "\nget_window_class: "..class..
    "\nget_window_role: "..get_window_role()..
    "\nget_window_type: "..t..
    "\nget_window_xid: "..xid..
    "\nx,y: "..x.." "..y..
    "\nw,h: "..w.." "..h..
    "\nxs: "..xs..
    "\n---")

w_major_factor = (xs > 1400) and 0.65 or 1.00
w_minor_factor = (xs > 1400) and 0.35 or 0.50

name = string.gsub(string.lower(get_application_name()), "%s+", "")
role = string.gsub(string.lower(get_window_role()), "%s+", "")
debug_print("name: "..name.."\n")
if (string.find(class, "skype")) then
    size_window(xid, "-h")
    move_window(xid, "0")
elseif (string.find(class, "pidgin") or
        string.find(class, "telegram")) then
    size_window(xid, "-l")
    move_window(xid, "0")
elseif (((string.match(name, "firefox") or
            string.match(class, "firefox")) and not 
            string.match(role, "about")) or
        string.find(class, "calibre") or
        string.find(name, "e%-bookviewer") or
        string.find(name, "fbreader") or
        string.match(name, "zathura")) then
    -- set_window_geometry(0,0,xs*w_major_factor,ys)
    size_window(xid, "-h")
elseif (string.match(name, "thunderbird")) then
    size_window(xid, "-h")
    move_window(xid, "1")
elseif (string.match(name, "keepassx")) then
    size_window(xid, "-l")
    move_window(xid, "1")
elseif (string.match(name, "keepassxc")) then
    size_window(xid, "-l")
    move_window(xid, "1")
elseif (string.match(name, "terminal") or
        string.match(name, "vim")) then
    -- set_window_geometry(xs*w_major_factor+1,0,xs*w_minor_factor-1,ys)
    size_window(xid, "-l")
    if (string.find(n, "tmux%[tasks%]")) then
        move_window(xid, "1")
    end
elseif ((string.match(class, "VirtualBox Manager") or
            string.match(name, "nautilus") or
            string.match(name, "pcmanfm") or
            string.match(name, "spacefm") or
            string.match(name, "thunar")) and not (
        string.find(n, "execute%s*file"))) then
    -- set_window_geometry(0,0,xs*0.50,ys)
    size_window(xid, "--half-left")
    move_window(xid, "3")
elseif (string.match(name, "spek")) then
    -- set_window_geometry(xs*0.50,ys*0.50,xs*0.50,ys)
    size_window(xid, "--half-right")
    move_window(xid, "3")
elseif (string.match(name, "calculator") or
        string.match(name, "deadbeef")) then
    -- set_window_geometry(xs*w_major_factor+1,ys*0.50,xs*w_minor_factor-1,ys*0.50)
    size_window(xid, "-m")
    move_window(xid, "3")
elseif (string.match(name, "transmission")) then
    -- set_window_geometry(xs*w_major_factor+1,0,xs*w_minor_factor-1,ys*0.50)
    size_window(xid, "--half-right-top")
elseif (string.match(name, "mpv") or
        string.find(name, "chocolate-doom") or
        string.find(name, "crispy-doom") or
        string.find(name, "dosbox") or
        string.find(name, "prboom") or
        string.find(name, "quakespasm") or
        string.find(name, "zdoom")) then
    -- set_window_geometry((xs-w)*0.50,(ys-h)*0.50,w,h)
    size_window(xid, "--move-center")
end
