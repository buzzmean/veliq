# Generates installer/assets/wizard-*.bmp from the approved brand SVGs.
# Usage (from the repository root): python3 installer/make-wizard-images.py .
# Requires rsvg-convert and Pillow; the BMP files are committed, the build does not run this.
import subprocess,io,sys
from PIL import Image,ImageDraw,ImageFont
root=sys.argv[1]; out=root+'/installer/assets/'
INK=(10,10,11); FAINT=(142,147,156); MUTED=(181,185,191)
def svg(path,w):
  png=subprocess.run(['rsvg-convert','-w',str(w),path],capture_output=True,check=True).stdout
  return Image.open(io.BytesIO(png)).convert('RGBA')
wm=root+'/app-ui/assets/img/veliq-wordmark-dark.svg'
sym=root+'/app-ui/assets/img/veliq-symbol-reverse.svg'
font=root+'/apps/desktop/Assets/Fonts/Onest-Medium.ttf'
# Side image of the welcome/finish pages: dark panel like .inst__side.
for scale,(w,h) in zip([100,125,150,175,200,225,250],[(164,314),(192,386),(246,459),(273,556),(328,604),(355,700),(410,797)]):
  img=Image.new('RGB',(w,h),INK); k=w/164
  mark=svg(wm,int(118*k)); img.paste(mark,(int(10*k),int(16*k)),mark)
  d=ImageDraw.Draw(img); f=ImageFont.truetype(font,max(9,int(12*k)))
  d.text((int(16*k),h-int(44*k)),'Нажал — работает.',font=f,fill=MUTED)
  d.rectangle([int(16*k),h-int(22*k),int(16*k)+int(24*k),h-int(22*k)+max(2,int(2*k))],fill=(240,80,42))
  img.save(out+f'wizard-{scale}.bmp')
for scale,(w,h) in zip([100,125,150,175,200,225,250],[(55,55),(64,68),(83,80),(92,97),(110,106),(119,123),(138,140)]):
  img=Image.new('RGB',(w,h),(255,255,255)); s=int(min(w,h)*0.86)
  m=svg(root+'/brand/icons/app-icon.svg',s); img.paste(m,((w-m.width)//2,(h-m.height)//2),m)
  img.save(out+f'wizard-small-{scale}.bmp')
print('ok')
