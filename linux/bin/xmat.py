#!/usr/bin/env python3

from dataclasses import dataclass
import argparse
import enum

from ewmh import EWMH
from Xlib import X
from Xlib.ext import randr

MAJOR_FACTOR = 0.65


class Geo(enum.IntEnum):
    HALF_BOTTOM = 1
    HALF_TOP = 2
    HALF_LEFT = 3
    HALF_RIGHT = 4
    MAJOR_LEFT = 5
    MAJOR_LEFT_BOTTOM = 6
    MAJOR_LEFT_TOP = 7
    MINOR_RIGHT = 8
    MINOR_RIGHT_BOTTOM = 9
    MINOR_RIGHT_TOP = 10
    MOVE_BOTTOM = 11
    MOVE_TOP = 12
    MOVE_LEFT = 13
    MOVE_RIGHT = 14
    MOVE_CENTER = 15
    DECREMENT_BOTTOM = 16
    DECREMENT_TOP = 17
    DECREMENT_LEFT = 18
    DECREMENT_RIGHT = 19
    INCREMENT_BOTTOM = 20
    INCREMENT_TOP = 21
    INCREMENT_LEFT = 22
    INCREMENT_RIGHT = 23

    def __str__(self):
        return self.name.lower()

    def __repr__(self):
        return str(self)

    @staticmethod
    def argparse(s):
        try:
            return Geo[s.upper()]
        except KeyError:
            return s


@dataclass
class Frame:
    left: int
    right: int
    top: int
    bottom: int


@dataclass
class Rect:
    x: int
    y: int
    width: int
    height: int


def absolute_geometry(win, root):
    geo = win.get_geometry()
    x, y = geo.x, geo.y
    while True:
        prev_id = win.id
        parent = win.query_tree().parent
        if parent.id == prev_id:
            break

        parent_geo = parent.get_geometry()
        x += parent_geo.x
        y += parent_geo.y
        if parent.id == root.id:
            break
        win = parent
    return Rect(x, y, geo.width, geo.height)


def intersect(src1: Rect, src2: Rect) -> Rect:
    """
    References:
    * _gdk_x11_screen_get_monitor_work_area
    * https://gitlab.gnome.org/GNOME/gtk/blob/3.24.49/gdk/x11/gdkscreen-x11.c#L767
    """
    dest_x = max(src1.x, src2.x)
    dest_y = max(src1.y, src2.y)
    dest_x2 = min(src1.x + src1.width, src2.x + src2.width)
    dest_y2 = min(src1.y + src1.height, src2.y + src2.height)

    if dest_x2 > dest_x and dest_y2 > dest_y:
        return Rect(dest_x, dest_y, dest_x2 - dest_x, dest_y2 - dest_y)

    return None


def move_resize(ewmh, win, x, y, w, h):
    if x < 0 or y < 0 or w < 0 or h < 0:
        raise TypeError(f"Cannot move or resize with x={x},y={y},w={w},h={h}")

    ewmh.setWmState(win, 0, "_NET_WM_STATE_MAXIMIZED_HORZ")
    ewmh.setWmState(win, 0, "_NET_WM_STATE_MAXIMIZED_VERT")

    frame_extents = win.get_full_property(
        ewmh.display.get_atom("_GTK_FRAME_EXTENTS"), X.AnyPropertyType
    )
    if frame_extents is not None:
        frame = Frame(*frame_extents.value)
        x = max(0, x - frame.left)
        y = max(0, y - frame.top)
        w = w + frame.left + frame.right
        h = h + frame.top + frame.bottom
    else:
        # https://specifications.freedesktop.org/wm-spec/1.3/ar01s05.html#id-1.6.17
        frame_extents = win.get_full_property(
            ewmh.display.get_atom("_NET_FRAME_EXTENTS"), X.AnyPropertyType
        )
        if frame_extents is not None:
            frame = Frame(*frame_extents.value)
            w = w - frame.left - frame.right
            h = h - frame.top - frame.bottom

    ewmh.setMoveResizeWindow(win, 0, x, y, w, h)
    ewmh.display.flush()


def relative_move_resize(ewmh, workarea, win, x, y, w, h):
    if x < 0 or y < 0 or w < 0 or h < 0:
        raise TypeError(f"Cannot move or resize with x={x},y={y},w={w},h={h}")

    ewmh.setWmState(win, 0, "_NET_WM_STATE_MAXIMIZED_HORZ")
    ewmh.setWmState(win, 0, "_NET_WM_STATE_MAXIMIZED_VERT")

    frame_extents = win.get_full_property(
        ewmh.display.get_atom("_NET_FRAME_EXTENTS"), X.AnyPropertyType
    )
    if frame_extents is not None:
        frame = Frame(*frame_extents.value)
        x = max(workarea.x, x - frame.left)
        y = max(workarea.y, y - frame.top)

    # Always set width and height to original values, as some
    # window managers seem to ignore unset gravity flags and will
    # not preserve unmodified values...
    ewmh.setMoveResizeWindow(win, 0, x, y, w, h)
    ewmh.display.flush()


def step(workarea_width, win_width, factor):
    steps = [0.10, 0.25, 0.35, 0.50, 0.65, 0.75, 0.90, 1.00]
    workarea_steps = list(enumerate(int(x * workarea_width) for x in steps))
    i, closest_step = min(workarea_steps, key=lambda x: abs(x[1] - win_width))
    if factor > 0:
        if closest_step <= win_width:
            _, closest_step = workarea_steps[min(len(workarea_steps) - 1, i + factor)]
        return closest_step - win_width
    else:
        if closest_step >= win_width:
            _, closest_step = workarea_steps[max(0, i + factor)]
        return win_width - closest_step


if __name__ == "__main__":
    ewmh = EWMH()

    # Assume all desktops have the same workarea
    workarea = Rect(*ewmh.getWorkArea()[0:4])

    # Assume a single Xinerama screen
    screen = ewmh.display.screen(0)

    # Assume that a panel is present on all crtcs, taking the same
    # amount of space on each crtc. As the display workarea might
    # overcount the space to reduce when multiple monitors are
    # connected, we override that amount by the minimum
    # greater than zero height difference, which we will consider when computing the effective height of each crtc workarea.
    resources = randr.get_screen_resources(screen.root)
    crtc_geometries = []
    min_workarea_diff = 99999
    for output in resources.outputs:
        params = ewmh.display.xrandr_get_output_info(output, resources.config_timestamp)
        if not params.crtc:
            continue
        crtc = ewmh.display.xrandr_get_crtc_info(
            params.crtc, resources.config_timestamp
        )
        crtc_rect = Rect(crtc.x, crtc.y, crtc.width, crtc.height)
        crtc_workarea = intersect(workarea, crtc_rect)
        workarea_diff = crtc_rect.height - crtc_workarea.height
        if workarea_diff > 0 and min_workarea_diff > workarea_diff:
            min_workarea_diff = workarea_diff
        crtc_geometries.append(
            Rect(
                crtc_workarea.x, crtc_workarea.y, crtc_workarea.width, crtc_rect.height
            )
        )
    workareas = []
    for crtc_geometry in crtc_geometries:
        workareas.append(
            Rect(
                crtc_geometry.x,
                crtc_geometry.y,
                crtc_geometry.width,
                crtc_geometry.height - min_workarea_diff,
            )
        )

    parser = argparse.ArgumentParser()
    parser.add_argument("geo", type=Geo.argparse, choices=list(Geo), nargs="?")
    parser.add_argument("--workarea", action="store_true")
    parser.add_argument("--xid", type=lambda x: int(x, 0))
    args = parser.parse_args()

    win = None
    if args.xid:
        for candidate_win in ewmh.getClientListStacking():
            # print(
            #     hex(win.id),
            #     win.get_wm_class(),
            #     ewmh.getWmName(win).decode(errors="backslashreplace"),
            # )
            if candidate_win.id == args.xid:
                win = candidate_win
                break
        if win is None:
            raise RuntimeError(f"Could not list xid={hex(args.xid)}")
    else:
        win = ewmh.getActiveWindow()

    # Assume reparenting window manager.
    # In such cases, the client list gives us geometry relative to
    # the window's frame. Instead, we want geometry relative to
    # the monitor's origin.
    win_rect = absolute_geometry(win, screen.root)

    workarea = None
    largest_intersection = 0
    for candidate_workarea in workareas:
        intersect_rect = intersect(win_rect, candidate_workarea)
        if intersect_rect is not None:
            intersection = intersect_rect.width * intersect_rect.height
            if largest_intersection < intersection:
                workarea = candidate_workarea
                largest_intersection = intersection

    if args.workarea:
        print(f"{workarea.width},{workarea.height}")
    elif args.geo == Geo.HALF_BOTTOM:
        move_resize(
            ewmh,
            win,
            workarea.x,
            workarea.y + workarea.height // 2,
            workarea.width,
            workarea.height // 2,
        )
    elif args.geo == Geo.HALF_TOP:
        move_resize(
            ewmh,
            win,
            workarea.x,
            workarea.y,
            workarea.width,
            workarea.height // 2,
        )
    elif args.geo == Geo.HALF_LEFT:
        move_resize(
            ewmh,
            win,
            workarea.x,
            workarea.y,
            workarea.width // 2,
            workarea.height,
        )
    elif args.geo == Geo.HALF_RIGHT:
        move_resize(
            ewmh,
            win,
            workarea.width // 2 + workarea.x,
            workarea.y,
            workarea.width // 2,
            workarea.height,
        )
    elif args.geo == Geo.MAJOR_LEFT:
        move_resize(
            ewmh,
            win,
            workarea.x,
            workarea.y,
            int(workarea.width * MAJOR_FACTOR),
            workarea.height,
        )
    elif args.geo == Geo.MAJOR_LEFT_BOTTOM:
        move_resize(
            ewmh,
            win,
            workarea.x,
            workarea.y + workarea.height // 2,
            int(workarea.width * MAJOR_FACTOR),
            workarea.height // 2,
        )
    elif args.geo == Geo.MAJOR_LEFT_TOP:
        move_resize(
            ewmh,
            win,
            workarea.x,
            workarea.y,
            int(workarea.width * MAJOR_FACTOR),
            workarea.height // 2,
        )
    elif args.geo == Geo.MINOR_RIGHT:
        move_resize(
            ewmh,
            win,
            int(workarea.width * MAJOR_FACTOR) + workarea.x,
            workarea.y,
            int(workarea.width * (1 - MAJOR_FACTOR)),
            workarea.height,
        )
    elif args.geo == Geo.MINOR_RIGHT_BOTTOM:
        move_resize(
            ewmh,
            win,
            int(workarea.width * MAJOR_FACTOR) + workarea.x,
            workarea.y + workarea.height // 2,
            int(workarea.width * (1 - MAJOR_FACTOR)),
            workarea.height // 2,
        )
    elif args.geo == Geo.MINOR_RIGHT_TOP:
        move_resize(
            ewmh,
            win,
            int(workarea.width * MAJOR_FACTOR) + workarea.x,
            workarea.y,
            int(workarea.width * (1 - MAJOR_FACTOR)),
            workarea.height // 2,
        )
    elif args.geo == Geo.MOVE_BOTTOM:
        relative_move_resize(
            ewmh,
            workarea,
            win,
            win_rect.x,
            workarea.y + workarea.height - win_rect.height,
            win_rect.width,
            win_rect.height,
        )
    elif args.geo == Geo.MOVE_TOP:
        relative_move_resize(
            ewmh,
            workarea,
            win,
            win_rect.x,
            workarea.y,
            win_rect.width,
            win_rect.height,
        )
    elif args.geo == Geo.MOVE_LEFT:
        relative_move_resize(
            ewmh,
            workarea,
            win,
            workarea.x,
            win_rect.y,
            win_rect.width,
            win_rect.height,
        )
    elif args.geo == Geo.MOVE_RIGHT:
        relative_move_resize(
            ewmh,
            workarea,
            win,
            workarea.x + workarea.width - win_rect.width,
            win_rect.y,
            win_rect.width,
            win_rect.height,
        )
    elif args.geo == Geo.MOVE_CENTER:
        relative_move_resize(
            ewmh,
            workarea,
            win,
            workarea.x + (workarea.width - win_rect.width) // 2,
            workarea.y + (workarea.height - win_rect.height) // 2,
            win_rect.width,
            win_rect.height,
        )
    elif args.geo == Geo.DECREMENT_BOTTOM:
        amount = step(workarea.height, win_rect.height, -1)
        relative_move_resize(
            ewmh,
            workarea,
            win,
            win_rect.x,
            win_rect.y,
            win_rect.width,
            win_rect.height - amount,
        )
    elif args.geo == Geo.DECREMENT_TOP:
        amount = step(workarea.height, win_rect.height, -1)
        relative_move_resize(
            ewmh,
            workarea,
            win,
            win_rect.x,
            win_rect.y + amount,
            win_rect.width,
            win_rect.height - amount,
        )
    elif args.geo == Geo.DECREMENT_LEFT:
        amount = step(workarea.width, win_rect.width, -1)
        relative_move_resize(
            ewmh,
            workarea,
            win,
            win_rect.x + amount,
            win_rect.y,
            win_rect.width - amount,
            win_rect.height,
        )
    elif args.geo == Geo.DECREMENT_RIGHT:
        amount = step(workarea.width, win_rect.width, -1)
        relative_move_resize(
            ewmh,
            workarea,
            win,
            win_rect.x,
            win_rect.y,
            win_rect.width - amount,
            win_rect.height,
        )
    elif args.geo == Geo.INCREMENT_BOTTOM:
        amount = step(workarea.height, win_rect.height, +1)
        relative_move_resize(
            ewmh,
            workarea,
            win,
            win_rect.x,
            win_rect.y,
            win_rect.width,
            win_rect.height + amount,
        )
    elif args.geo == Geo.INCREMENT_TOP:
        amount = step(workarea.height, win_rect.height, +1)
        relative_move_resize(
            ewmh,
            workarea,
            win,
            win_rect.x,
            win_rect.y - amount,
            win_rect.width,
            win_rect.height + amount,
        )
    elif args.geo == Geo.INCREMENT_LEFT:
        amount = step(workarea.width, win_rect.width, +1)
        relative_move_resize(
            ewmh,
            workarea,
            win,
            win_rect.x - amount,
            win_rect.y,
            win_rect.width + amount,
            win_rect.height,
        )
    elif args.geo == Geo.INCREMENT_RIGHT:
        amount = step(workarea.width, win_rect.width, +1)
        relative_move_resize(
            ewmh,
            workarea,
            win,
            win_rect.x,
            win_rect.y,
            win_rect.width + amount,
            win_rect.height,
        )
