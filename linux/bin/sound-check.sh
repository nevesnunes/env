find /proc/asound/ | grep -i '/proc/asound/card.*/pcm.*/sub.*/status' | xargs cat | grep -iv 'closed'
