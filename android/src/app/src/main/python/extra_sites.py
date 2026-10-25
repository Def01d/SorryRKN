"""Explicit service domains; shared Google/Cloudflare names stay on the normal path."""
from service_catalog import DEFINITIONS, SHARED_DOMAINS
AI_HOSTS=tuple(d for s in DEFINITIONS for d in s['domains'])+SHARED_DOMAINS
INSTAGRAM_HOSTS=('instagram.com','cdninstagram.com','ig.me','fbcdn.net','facebook.com','facebook.net')
YOUTUBE_HOSTS=('youtube.com','youtube-nocookie.com','googlevideo.com','ytimg.com','youtu.be','youtubekids.com',
               'youtube.googleapis.com','youtubei.googleapis.com','youtubeembeddedplayer.googleapis.com',
               'yt3.ggpht.com','yt4.ggpht.com','yt3.googleusercontent.com','jnn-pa.googleapis.com',
               'wide-youtube.l.google.com','youtube-ui.l.google.com','ytimg.l.google.com','yt-video-upload.l.google.com')
DISCORD_HOSTS=('discord.com','discord.gg','discordapp.com','discordapp.net','discordcdn.com',
               'discord.media','discordstatus.com','discord.gift','dis.gd')
TELEGRAM_WS_HOSTS=tuple(f'kws{dc}{suffix}.web.telegram.org' for dc in range(1,6) for suffix in ('','-1'))

def matches(host,domains):
    if not isinstance(host,str):return False
    host=host.lower().rstrip('.')
    return any(host==domain or host.endswith('.'+domain) for domain in domains)
