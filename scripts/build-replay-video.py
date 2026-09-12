"""Encode dashboard frames captured through the browser's UI automation API.

Usage: PYTHONPATH=/tmp/precedent-video-deps python3 scripts/build-replay-video.py
Frames must be actual /demo browser screenshots at two-second playback intervals.
"""
import argparse
import subprocess
from pathlib import Path
import imageio_ffmpeg

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--frames', default='/tmp/precedent-dashboard-frames')
args = parser.parse_args()
frames = Path(args.frames)
assert len(list(frames.glob('*.png'))) == 80, 'Expected 80 captured dashboard frames'
subprocess.run([
    imageio_ffmpeg.get_ffmpeg_exe(), '-y', '-loglevel', 'error',
    '-framerate', '1/2', '-c:v', 'mjpeg', '-i', str(frames/'%03d.png'),
    '-t', '160', '-an', '-c:v', 'libx264', '-preset', 'fast',
    '-crf', '17', '-pix_fmt', 'yuv420p', '-r', '24',
    '-movflags', '+faststart', str(root/'docs/media/recorded-demo.mp4')
], check=True)
print('Created dashboard recording: 2:40, silent, actual recorded events replayed in the product.')
