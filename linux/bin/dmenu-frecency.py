#!/usr/bin/env python
"""Dmenu launcher with history sorted by frecency.

Usage:
    dmenu-frecency [--read-apps]

Options:
    --read-apps         rereads all .desktop files.
"""

from docopt import docopt
import os
import sys
import xdg.BaseDirectory
from xdg.DesktopEntry import DesktopEntry
from subprocess import Popen, PIPE
from datetime import datetime
from collections import defaultdict
import pickle
import re
import gzip
import json
import tempfile
import shlex


CONFIG_DIR = xdg.BaseDirectory.save_config_path('dmenu-frecency')


# Python 2 compatibility
try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError


class Application:
    def __init__(self, name, command_line, mtime=None, path=None, is_desktop=False):
        self.name = name
        self.path = path
        self.command_line = command_line
        self.is_desktop = is_desktop
        self.show_command = False
        if mtime is None:
            self.mtime = datetime.now()
        else:
            self.mtime = mtime

    def run(self):
        if os.fork() == 0:
            if self.path:
                os.chdir(self.path)
            os.execvp(self.command_line[0], self.command_line)

    def __lt__(self, other):
        return (self.is_desktop, self.mtime) < (other.is_desktop, other.mtime)

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return "<Application: {} {!r}>".format(self.name, self.command_line)


STATE_VERSION = 4


def get_command(desktop_entry):
    tokens = []
    for token in shlex.split(desktop_entry.getExec()):
        if token == '%i':
            if desktop_entry.getIcon():
                tokens.append('--icon')
                tokens.append(desktop_entry.getIcon())
        else:
            i = 0
            newtok = ""
            nc = len(token)
            while i < nc:
                c = token[i]
                if c == '%' and i < nc - 1:
                    i += 1
                    code = token[i]
                    if code == 'c' and desktop_entry.getName():
                        newtok += desktop_entry.getName()
                    elif code == '%':
                        newtok += '%'
                else:
                    newtok += c
                i += 1
            if newtok:
                tokens.append(newtok)
    return tuple(tokens)


class LauncherState:
    STATE_FILENAME = os.path.join(CONFIG_DIR, 'state')

    def __init__(self, config):
        self.version = STATE_VERSION
        self.config = config
        self.find_apps()
        self.apps_generated_at = datetime.now()
        self.visits = defaultdict(list)
        self.visit_count = defaultdict(int)
        self.app_last_visit = None
        self.frecency_cache = {}

    def apps_by_frecency(self):
        app_last_visit = self.app_last_visit if self.config['preselect-last-visit'] else None
        if app_last_visit is not None:
            yield app_last_visit
        for app, frec in sorted(self.frecency_cache.items(), key=lambda x: (-x[1], x[0])):
            if app_last_visit is None or app_last_visit != app:
                yield app
        for app in self.sorted_apps:
            if app not in self.frecency_cache:
                if app_last_visit is None or app_last_visit != app:
                    yield app

    def add_visit(self, app):
        if not app.is_desktop and app.command_line in self.command_apps:
            app = self.command_apps[app.command_line]
            app.show_command = True
        try:
            self.sorted_apps.remove(app)
        except ValueError:
            pass # not in list
        vs = self.visits[app]
        now = datetime.now()
        vs.append(now)
        self.visit_count[app] += 1
        self.visits[app] = vs[-self.config['frecency-visits']:]
        self.app_last_visit = app if self.config['preselect-last-visit'] else None
    
    def update_frecencies(self):
        for app in self.visits.keys():
            self.frecency_cache[app] = self.frecency(app)

    def frecency(self, app):
        points = 0
        for v in self.visits[app]:
            days_ago = (datetime.now() - v).days
            if days_ago < 4:
                points += 100
            elif days_ago < 14:
                points += 70
            elif days_ago < 31:
                points += 50
            elif days_ago < 90:
                points += 30
            else:
                points += 10

        return int(self.visit_count[app] * points / len(self.visits[app]))

    @classmethod
    def load(cls, config):
        try:
            with gzip.open(cls.STATE_FILENAME, 'rb') as f:
                obj = pickle.load(f)
            version = getattr(obj, 'version', 0)
            if version < STATE_VERSION:
                new_obj = cls(config)
                if version <= 1:
                    for app, vs in obj.visits.items():
                        vc = obj.visit_count[app]
                        app.is_desktop = True
                        new_obj.visit_count[app] = vc
                        new_obj.visits[app] = vs
                new_obj.find_apps()
                new_obj.clean_cache()
                new_obj.update_frecencies()
                new_obj.config = config
                return new_obj
            else:
                obj.config = config
                return obj
        except FileNotFoundError:
            return cls(config)

    def save(self):
        with tempfile.NamedTemporaryFile(
                'wb',
                dir=os.path.dirname(self.STATE_FILENAME),
                delete=False) as tf:
            with gzip.open(tf, 'wb') as gzipf:
                pickle.dump(self, gzipf)
            tempname = tf.name
        os.rename(tempname, self.STATE_FILENAME)

    def find_apps(self):
        self.apps = {}
        self.command_apps = {}
        if self.config['scan-desktop-files']:
            for applications_directory in xdg.BaseDirectory.load_data_paths("applications"):
                if os.path.exists(applications_directory):
                    for dirpath, dirnames, filenames in os.walk(applications_directory):
                        for f in filenames:
                            if f.endswith('.desktop'):
                                full_filename = os.path.join(dirpath, f)
                                self.add_desktop(full_filename)

        if self.config['scan-path']:
            for pathdir in os.environ["PATH"].split(os.pathsep):
                pathdir = pathdir.strip('"')
                if not os.path.isdir(pathdir):
                    continue

                for f in os.listdir(pathdir):
                    filename = os.path.join(pathdir, f)
                    if os.path.isfile(filename) and os.access(filename, os.X_OK):
                        app = Application(
                                name=f,
                                command_line=(f,),
                                mtime=datetime.fromtimestamp(os.path.getmtime(filename)))
                        self.add_app(app)
        self.sorted_apps = sorted(self.apps.values(), reverse=True)

    def add_desktop(self, filename):
        try:
            d = DesktopEntry(filename)
            if d.getHidden() or d.getNoDisplay() or d.getTerminal() or d.getType() != 'Application':
                return
            app = Application(
                    name=d.getName(),
                    command_line=get_command(d),
                    mtime=datetime.fromtimestamp(os.path.getmtime(filename)),
                    is_desktop=True)
            if d.getPath():
                app.path = d.getPath()
            self.add_app(app)
        except (xdg.Exceptions.ParsingError,
                xdg.Exceptions.DuplicateGroupError,
                xdg.Exceptions.DuplicateKeyError):
            pass

    def add_app(self, app):
        if app.command_line not in self.command_apps:
            self.apps[app.name] = app
            self.command_apps[app.command_line] = app

    def clean_cache(self):
        for app in list(self.frecency_cache.keys()):
            if app.is_desktop and app.name not in self.apps:
                del self.frecency_cache[app]
        if self.app_last_visit is not None and self.app_last_visit.name not in self.apps:
            self.app_last_visit = None


class DmenuFrecency:
    CONFIG_FILENAME = os.path.join(CONFIG_DIR, 'config.json')
    DEFAULT_CONFIG = {
        'dmenu': 'dmenu',
        'dmenu-args': ['-i'],
        'cache-days': 1,
        'frecency-visits': 10,
        'preselect-last-visit': False,
        'scan-desktop-files': True,
        'scan-path': False,
    }
    NAME_WITH_COMMAND = re.compile(r"(.+) \([^()]+\)")

    def __init__(self, arguments):
        self.read_apps = arguments['--read-apps']
        self.load_config()
        self.state = LauncherState.load(self.config)
        assert self.state, "Failed to load state."

    def load_config(self):
        self.config = {}
        self.config.update(self.DEFAULT_CONFIG)
        try:
            with open(self.CONFIG_FILENAME, 'r') as f:
                self.config.update(json.load(f))
        except FileNotFoundError:
            with open(self.CONFIG_FILENAME, 'w') as f:
                json.dump(self.config, f, sort_keys=True, indent=4)
                f.write('\n')

    def main(self):
        if self.read_apps:
            self.state.find_apps()
            self.state.clean_cache()
            self.state.save()
            return

        dmenu = Popen([self.config['dmenu']] + self.config['dmenu-args'], stdin=PIPE, stdout=PIPE)
        for app in self.state.apps_by_frecency():
            app_name = app.name.encode('utf-8')
            dmenu.stdin.write(app_name)
            if app.show_command and app.name != app.command_line[0]:
                dmenu.stdin.write(" ({})".format(' '.join(app.command_line)).encode('utf-8'))
            dmenu.stdin.write(b'\n')
        stdout, stderr = dmenu.communicate()
        result = stdout.decode('utf-8').strip()

        if not result:
            return

        if result in self.state.apps:
            app = self.state.apps[result]
        else:
            m = self.NAME_WITH_COMMAND.match(result)
            if m and m.group(1) in self.state.apps:
                app = self.state.apps[m.group(1)]
            else:
                app = Application(
                        name=result,
                        command_line=tuple(shlex.split(result)))

        app.run()

        self.state.add_visit(app)
        self.state.update_frecencies()

        if (datetime.now() - self.state.apps_generated_at).days >= self.config['cache-days']:
            self.state.find_apps()
            self.state.clean_cache()
        self.state.save()


if __name__ == '__main__':
    arguments = docopt(__doc__, version="0.1")
    DmenuFrecency(arguments).main()
