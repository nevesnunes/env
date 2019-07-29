transmission-edit -a 'udp://%%%/announce' %%%.torrent
transmission-remote -n user:pass --torrent all --tracker-add 'udp://%%%/announce'
env TR_AUTH='user:pass' transmission-remote -ne --torrent all --tracker-add 'udp://%%%/announce'
