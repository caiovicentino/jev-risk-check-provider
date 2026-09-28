import sys, os, numpy as np
os.environ['PYTORCH_ENABLE_MPS_FALLBACK'] = '1'
from kokoro import KPipeline
import soundfile as sf

def main():
    text, voice, out = sys.argv[1], sys.argv[2], sys.argv[3]
    lang = "a" if voice.startswith(("a", "b")) else "p"
    pipe = KPipeline(lang_code=lang, device="mps")
    chunks = list(pipe(text, voice=voice, speed=0.8 if lang == "p" else 1.0))
    audio = np.concatenate([c[2].numpy() for c in chunks]) if len(chunks) > 1 else chunks[0][2].numpy()
    sf.write(out, audio, 24000)

main()
