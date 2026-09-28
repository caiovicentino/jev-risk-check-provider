# Draft video generator

Renders the hackathon draft videos (slides + TTS narration + terminal frames) from the kit scripts.

    pip3 install Pillow edge-tts   # ffmpeg via brew
    python3 tools/video/videos.py all

Fonts (Space Grotesk, IBM Plex Mono) are fetched from Google Fonts at render time — download to
`/tmp/paysol-video/fonts/` first (see videos.py header). Draft MP4s are written to /tmp/paysol-video/.
Timing targets: week1 ≤60s, pitch ~2:30, demo ≤3:00. Narration is pt-BR (edge-tts AntonioNeural) —
the final videos are recorded by the founder; these drafts exist to validate flow and copy.
