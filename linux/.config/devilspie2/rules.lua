-- For debug_print() output, run:
-- devilspie2 --debug

-- To invoke an external script:
-- os.execute(os.getenv("HOME").."/bin/script.sh")

function size_window (xid, operation)
    os.execute(os.getenv("HOME").."/bin/xsize.sh --id "..xid.." "..operation)
end

t = string.upper(get_window_type())
window_name = string.gsub(string.lower(get_window_name()), "%s+", "")
if (string.match(window_name, "scratchpad") or
        string.match(t, "WINDOW_TYPE_DIALOG") or
        string.match(t, "WINDOW_TYPE_MENU") or
        string.match(t, "WINDOW_TYPE_UTILITY") or
        string.match(t, "WINDOW_TYPE_SPLASHSCREEN")) then
    return
end

xid = get_window_xid()
x,y,w,h = get_window_geometry()
xs,ys = get_screen_geometry()
debug_print("get_window_name: "..get_window_name()..
        "\nget_application_name: "..get_application_name()..
        "\nget_window_role: "..get_window_role()..
        "\nget_window_type: "..get_window_type()..
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
if ((string.match(name, "firefox") and not 
        string.match(role, "about")) or
        string.find(name, "e%-bookviewer") or
        string.find(name, "fbreader") or
        string.match(name, "thunderbird") or
        string.match(name, "zathura")) then
    -- set_window_geometry(0,0,xs*w_major_factor,ys)
    size_window(xid, "-h")
elseif (string.match(name, "keepassx") or
        string.find(name, "telegram") or
        string.match(name, "terminal") or
        string.match(name, "vim")) then
    -- set_window_geometry(xs*w_major_factor+1,0,xs*w_minor_factor-1,ys)
    size_window(xid, "-l")
elseif ((string.match(name, "nautilus") or
        string.match(name, "pcmanfm") or
        string.match(name, "spacefm") or
        string.match(name, "thunar")) and not (
        string.find(window_name, "execute%s*file"))) then
    -- set_window_geometry(0,0,xs*0.50,ys)
    size_window(xid, "--half-left")
elseif (string.match(name, "spek")) then
    -- set_window_geometry(xs*0.50,ys*0.50,xs*0.50,ys)
    size_window(xid, "--half-right")
elseif (string.match(name, "calculator") or
        string.match(name, "deadbeef")) then
    -- set_window_geometry(xs*w_major_factor+1,ys*0.50,xs*w_minor_factor-1,ys*0.50)
    size_window(xid, "-m")
elseif (string.match(name, "transmission")) then
    -- set_window_geometry(xs*w_major_factor+1,0,xs*w_minor_factor-1,ys*0.50)
    size_window(xid, "--half-right-top")
elseif (string.match(name, "mpv") or
        string.find(name, "chocolate-doom") or
        string.find(name, "crispy-doom") or
        string.find(name, "dosbox") or
        string.find(name, "prboom") or
        string.find(name, "zdoom")) then
    -- set_window_geometry((xs-w)*0.50,(ys-h)*0.50,w,h)
    size_window(xid, "--move-center")
end
