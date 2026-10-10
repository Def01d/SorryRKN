"""Explicit service domains; shared Google/Cloudflare names stay on the normal path."""
AI_HOSTS=('chatgpt.com','openai.com','oaistatic.com','oaiusercontent.com','oaistatsig.com',
          'cdn.openaimerge.com','cdn.workos.com','forwarder.workos.com',
          'frontend-apps-multi-region.workos.com','images.workoscdn.com','setup.workos.com',
          'workos.imgix.net','challenges.cloudflare.com',
          'claude.ai','anthropic.com','claudeusercontent.com',
          'gemini.google.com','bard.google.com','aistudio.google.com','generativelanguage.googleapis.com',
          'gemini-pa.googleapis.com','proactivebackend-pa.googleapis.com',
          'alkalimakersuite-pa.googleapis.com','alkalimakersuite-pa.clients6.google.com')
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
