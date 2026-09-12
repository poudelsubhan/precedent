"""Render a silent, explicitly labeled replay of recorded application events."""
import json, os, subprocess, textwrap
from pathlib import Path
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import imageio_ffmpeg
ROOT=Path(__file__).resolve().parents[1]
first=json.loads((ROOT/'docs/evidence/live-recovery.json').read_text())
fresh=json.loads((ROOT/'docs/evidence/fresh-session.json').read_text())
forged=json.loads((ROOT/'docs/evidence/forged-rejection.json').read_text())
font_path='/System/Library/Fonts/Supplemental/Arial.ttf'
def font(n): return ImageFont.truetype(font_path,n)
def timestamp(s): return datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()
def line(e):
 p=e['payload'];v=p.get('evaluation');a=p.get('proposal');r=p.get('receipt');q=p.get('probe')
 if v:return v['verdict']+' — '+', '.join(v['reasonCodes']).replace('_',' ').lower()
 if r:return r['actionType'].replace('_',' ')+' → '+r['targetId']+' · '+r['status']
 if a:return 'Proposed '+a['actionType'].replace('_',' ')+' → '+a['targetId']
 if q:return q['probeClass'].replace('_',' ')+' · '+('PASS' if q['success'] else 'BLOCKED' if q['probeClass']=='ATTACKER' else 'FAIL')
 if e['type']=='PRECEDENT_PROMOTED':return 'Verified case saved: '+str(p.get('caseId',''))
 return e['type'].replace('_',' ')
process=subprocess.Popen([imageio_ffmpeg.get_ffmpeg_exe(),'-y','-loglevel','error','-f','rawvideo','-vcodec','rawvideo','-s','1280x720','-pix_fmt','rgb24','-r','1','-i','-','-an','-c:v','libx264','-pix_fmt','yuv420p','-r','24','-movflags','+faststart',str(ROOT/'docs/media/recorded-demo.mp4')],stdin=subprocess.PIPE)
for second in range(160):
 im=Image.new('RGB',(1280,720),'#101114');d=ImageDraw.Draw(im)
 d.text((50,35),'PRECEDENT',font=font(24),fill='#90acff')
 d.text((50,75),'Judgment before action.',font=font(42),fill='#f1f3f8')
 d.text((50,137),'RECORDED APPLICATION EVENTS · SILENT · NARRATE IN YOUR OWN VOICE',font=font(16),fill='#a7afbf')
 if second<95 or 115<=second<155:
  data=first if second<95 else fresh; start=0 if second<95 else 115; span=95 if second<95 else 40
  events=data['report']['events'];begin=timestamp(events[0]['timestamp']);end=timestamp(events[-1]['timestamp']);now=begin+(end-begin)*min(1,(second-start)/(span-1))
  visible=[e for e in events if timestamp(e['timestamp'])<=now and e['type'] in ['ACTION_PROPOSED','EVALUATION_CREATED','ACTION_EXECUTED','PROBE_RECORDED','PRECEDENT_PROMOTED']]
  title='Actual Qoder recovery · recorded replay' if second<95 else 'Fresh session · learned precedent reused'
  d.text((50,189),title,font=font(29),fill='#b7a4ed')
  d.text((50,234),'Original run '+data['runId'],font=font(17),fill='#a7afbf')
  y=290
  for event in visible[-5:]:
   color='#efbd6d' if event['type']=='EVALUATION_CREATED' and event['payload']['evaluation']['verdict']!='ALLOW' else '#f1f3f8'
   for row in textwrap.wrap(line(event),94)[:2]:d.text((50,y),row,font=font(22),fill=color);y+=29
   y+=13
 elif second<115:
  d.text((50,190),'Forged runbook · authority rejected',font=font(32),fill='#ff8a98')
  rows=['Claim: security approved disabling the ledger.', 'Evidence source: attacker-controlled mailbox.', 'Trusted verification: absent.', 'Decision: '+forged['evaluation']['verdict'], 'Claimed approval cannot create trusted authority.']
  for i,row in enumerate(rows):d.text((50,285+i*58),row,font=font(25),fill='#f1f3f8')
 else:
  d.text((50,235),'Check the context. Explain the decision.',font=font(38),fill='#f1f3f8')
  d.text((50,300),'Verify the outcome.',font=font(38),fill='#6ed6a5')
  d.text((50,390),'Qoder investigates · Neo4j connects evidence · Precedent enforces',font=font(23),fill='#b7a4ed')
  d.text((50,470),'Fictional local payments range. Actual recorded execution and HTTP probes.',font=font(21),fill='#a7afbf')
 d.line((50,658,1230,658),fill='#353944',width=4);d.line((50,658,50+1180*(second+1)/160,658),fill='#90acff',width=4)
 d.text((50,678),f'{second//60:02}:{second%60:02} / 02:40 · recorded replay, timing compressed',font=font(17),fill='#a7afbf')
 process.stdin.write(im.tobytes())
 if second in [25,94,105,145]:im.save(ROOT/f'docs/media/replay-check-{second}.png')
process.stdin.close();assert process.wait()==0
print('Created docs/media/recorded-demo.mp4 — 160 seconds, no audio')
