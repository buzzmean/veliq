#!/usr/bin/env python3
"""Explicit operator actions, after deployment approval. Linux/root/local PostgreSQL.
Issue creates a DISABLED code and writes it once into a new root-only file.
Never print the code, its hash, database errors or connection credentials.
"""
import argparse, hashlib, json, os, re, secrets, stat, subprocess
from pathlib import Path

OWNER_ID='00000000000000000000000000000000'
OWNER_EMAIL='redacted-person@example.invalid'

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('action',choices=['issue-owner','issue-club','approve-club','enable','disable'])
 p.add_argument('--database',required=True)
 p.add_argument('--port',type=int,default=5432)
 p.add_argument('--id',help='Campaign or club account ID, never the secret code')
 p.add_argument('--output',help='New file in an existing root-owned 0700 directory')
 p.add_argument('--confirm-club-rules',action='store_true')
 p.add_argument('--confirmed-club-verification',action='store_true',help='Operator independently verified this club')
 p.add_argument('--club-reference',help='Stable opaque ID assigned by owner to the verified real club, not supplied by applicant')
 a=p.parse_args()
 if os.name!='posix' or os.geteuid()!=0:raise ValueError('ROOT_LINUX_REQUIRED')
 if not re.fullmatch('[A-Za-z0-9_]+',a.database) or not 1<=a.port<=65535:raise ValueError('DATABASE_INVALID')
 def sql(query):
  r=subprocess.run(['runuser','-u','postgres','--','psql','-X','-q','-A','-t','-p',str(a.port),'-d',a.database,'-v','ON_ERROR_STOP=1'],input=query.encode(),capture_output=True,timeout=20)
  if r.returncode:raise ValueError('DATABASE_OPERATION_FAILED')
  return r.stdout.decode().strip()
 if a.action.startswith('issue-'):
  target=Path(a.output or '')
  if not target.is_absolute() or target.exists() or target.is_symlink():raise ValueError('NEW_ABSOLUTE_OUTPUT_REQUIRED')
  parent=target.parent;meta=parent.lstat()
  if any((d/'.git').exists() for d in [parent,*parent.parents]):raise ValueError('OUTPUT_INSIDE_REPOSITORY')
  if parent.resolve()!=parent or not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or stat.S_IMODE(meta.st_mode)!=0o700:raise ValueError('ROOT_PRIVATE_DIRECTORY_REQUIRED')
  kind='owner-test' if a.action=='issue-owner' else 'club-launch'
  if sql("SELECT count(*) FROM promotions WHERE kind='"+kind+"';")!='0':raise ValueError('CAMPAIGN_EXISTS_NO_REISSUE')
  if kind=='owner-test' and sql("SELECT count(*) FROM accounts WHERE id='"+OWNER_ID+"' AND email='"+OWNER_EMAIL+"' AND account_type='player' AND NOT disabled;")!='1':raise ValueError('OWNER_IDENTITY_MISMATCH')
  raw=secrets.token_bytes(32);code=raw.hex();digest=hashlib.sha256(b'veliq:promotion:v1\x00'+raw).hexdigest();campaign=secrets.token_hex(16)
  fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as out:out.write(code+'\n');out.flush();os.fsync(out.fileno())
  account="'"+OWNER_ID+"'" if kind=='owner-test' else 'NULL'
  discount,capacity=(99,1) if kind=='owner-test' else (30,20)
  sql("BEGIN; INSERT INTO promotions(id,code_hash,kind,account_id,discount,capacity) VALUES('"+campaign+"',decode('"+digest+"','hex'),'"+kind+"',"+account+","+str(discount)+","+str(capacity)+"); INSERT INTO audit_log(actor,action,entity_id) VALUES('operator:local','promotion.created','"+campaign+"'); COMMIT;")
  print(json.dumps({'status':'PASS','campaign_id':campaign,'enabled':False,'secret_file':str(target)}));return
 if not a.id or not re.fullmatch('[0-9a-f]{32}',a.id):raise ValueError('ID_INVALID')
 if a.action=='approve-club':
  if not a.confirmed_club_verification:raise ValueError('CLUB_VERIFICATION_REQUIRED')
  if not a.club_reference or not re.fullmatch('[a-zA-Z0-9_-]{8,64}',a.club_reference):raise ValueError('CLUB_REFERENCE_REQUIRED')
  if sql("SELECT count(*) FROM accounts WHERE id='"+a.id+"' AND account_type='club' AND NOT disabled;")!='1':raise ValueError('CLUB_ACCOUNT_REQUIRED')
  existing=sql("SELECT club_reference FROM promotion_club_approvals WHERE account_id='"+a.id+"';")
  if existing and existing!=a.club_reference:raise ValueError('CLUB_REFERENCE_CONFLICT')
  sql("BEGIN; INSERT INTO promotion_club_approvals(account_id,club_reference) VALUES('"+a.id+"','"+a.club_reference+"') ON CONFLICT(account_id) DO NOTHING; INSERT INTO audit_log(actor,action,entity_id) VALUES('operator:local','promotion.club-approved','"+a.id+"'); COMMIT;")
 else:
  kind=sql("SELECT kind FROM promotions WHERE id='"+a.id+"';")
  if kind not in ('owner-test','club-launch'):raise ValueError('CAMPAIGN_NOT_FOUND')
  if kind=='club-launch' and a.action=='enable' and not a.confirm_club_rules:raise ValueError('CLUB_RULES_CONFIRMATION_REQUIRED')
  enabled='true' if a.action=='enable' else 'false'
  sql("BEGIN; UPDATE promotions SET enabled="+enabled+" WHERE id='"+a.id+"'; INSERT INTO audit_log(actor,action,entity_id) VALUES('operator:local','promotion."+a.action+"','"+a.id+"'); COMMIT;")
 print(json.dumps({'status':'PASS','action':a.action,'id':a.id}))

if __name__=='__main__':
 try:main()
 except Exception as error:
  safe={'ROOT_LINUX_REQUIRED','DATABASE_INVALID','NEW_ABSOLUTE_OUTPUT_REQUIRED','ROOT_PRIVATE_DIRECTORY_REQUIRED','CAMPAIGN_EXISTS_NO_REISSUE','OWNER_IDENTITY_MISMATCH','ID_INVALID','CLUB_ACCOUNT_REQUIRED','CAMPAIGN_NOT_FOUND','CLUB_RULES_CONFIRMATION_REQUIRED','DATABASE_OPERATION_FAILED','OUTPUT_INSIDE_REPOSITORY','CLUB_VERIFICATION_REQUIRED','CLUB_REFERENCE_REQUIRED','CLUB_REFERENCE_CONFLICT'}
  code=str(error) if isinstance(error,ValueError) and str(error) in safe else 'SAFE_STOP'
  print(json.dumps({'status':'STOPPED','code':code}));raise SystemExit(1)
