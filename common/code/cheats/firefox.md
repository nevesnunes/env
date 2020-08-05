# memory usage

about:performance
    memory usage by tabs and extensions
about:memory?file=/home/fn/Downloads/memory-report.json.gz
about:memory?verbose
    https://developer.mozilla.org/en-US/docs/Mozilla/Performance/about:memory

```javascript
// Multi-process usage (Electrolysis, e10s)
user_pref("browser.tabs.remote.autostart", false);

// https://support.mozilla.org/en-US/kb/performance-settings
user_pref("dom.ipc.processCount", 1);
// Entries in tab history (back/next)
user_pref("browser.sessionhistory.max_entries", 5);
// http://kb.mozillazine.org/Browser.sessionhistory.max_total_viewers
user_pref("browser.sessionhistory.max_total_viewers", 2);
```

# navigation

C-l % = filter by open tabs
C-l * = filter by favorites

https://support.mozilla.org/en-US/kb/address-bar-autocomplete-firefox#w_changing-results-on-the-fly
chrome://flags/#omnibox-tab-switch-suggestions

# session data

```bash
cd ~/.mozilla/firefox/170qal6w.default/sessionstore-backups/
python3 ~/bin/mozlz4a.py -d recovery.jsonlz4 previous.js
cp previous.js sessionstore.js
```

# zoom

https://superuser.com/questions/1270927/how-to-set-default-web-page-size-in-firefox

FullZoom._cps2.setGlobal(FullZoom.name,1.2,gBrowser.selectedBrowser.loadContext);
FullZoom._cps2.removeGlobal(FullZoom.name,gBrowser.selectedBrowser.loadContext);

browser/base/content/browser-fullZoom.js

```javascript
FullZoom._cps2.getGlobal(FullZoom.name, gBrowser.selectedBrowser.loadContext, {
    handleResult: function (pref) { value = pref.value; },
    handleCompletion: (reason) => {
        this._globalValue = this._ensureValid(value);
        resolve(this._globalValue);
    }});
```

|| about:config > zoom.minPercent

|| https://bugzilla.mozilla.org/show_bug.cgi?id=1590485

# user agent

about:config
    general.useragent.override

# profiles

```bash
# create
firefox -no-remote -CreateProfile "foo $HOME/sandbox/opt/firefox-foo"
# run
firefox -no-remote -profile "$HOME/sandbox/opt/firefox-foo"
```

https://developer.mozilla.org/en-US/docs/Mozilla/Command_Line_Options#User_Profile

# Process index 

From `about:memory`:

- Main Process
- Web Content => limited by: `dom.ipc.processCount`
- WebExtensions
- Privileged Content
- RDD => Media decoders, reference: https://wiki.mozilla.org/Security/Sandbox/Process_model#Remote_Data_Decoder_.28RDD.29
    - [1538195 \- AV1 playback uses significantly more CPU when RDD is enabled](https://bugzilla.mozilla.org/show_bug.cgi?id=1538195)
    - [1539043 \- Reduce / remove copy and memory allocation when using RemoteDataDecoder \(decoder side\)](https://bugzilla.mozilla.org/show_bug.cgi?id=1539043)

On multiple windows, one child's cmdline includes: parentBuildID

[1500150 \- Setting dom\.ipc\.processCount=1 still creates multiple content processes](https://bugzilla.mozilla.org/show_bug.cgi?id=1500150)


