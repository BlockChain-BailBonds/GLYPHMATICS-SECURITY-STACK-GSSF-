#!/usr/bin/env python3
import hashlib,hmac,itertools,json,subprocess,sys
from collections import deque
D_L=b'QMTO/LAMPORT/v1'; D_S=b'QMTO/STATE/v1'; D_I=b'QMTO/SPEND/v1'; D_M=b'QMTO/MERKLE/v1'
def H(x): return hashlib.sha256(x).digest()
def bits(m):
 d=H(m); return [(b>>s)&1 for b in d for s in range(7,-1,-1)]
class Lamport:
 def __init__(self,seed):
  self.p=[tuple(hmac.new(seed,D_L+i.to_bytes(2,'big')+bytes([j]),hashlib.sha256).digest() for j in (0,1)) for i in range(256)]; self.used=False
 def pub(self): return tuple((H(a),H(b)) for a,b in self.p)
 def root(self): return H(b''.join(a+b for a,b in self.pub()))
 def sign(self,m):
  if self.used: raise RuntimeError('one-time key reused')
  self.used=True; q=bits(m); return tuple(self.p[i][q[i]] for i in range(256))
 @staticmethod
 def verify(pub,m,sig):
  q=bits(m); return len(sig)==256 and all(hmac.compare_digest(H(sig[i]),pub[i][q[i]]) for i in range(256))
def leaf(x): return H(D_M+b'L'+x)
def node(a,b): return H(D_M+b'N'+a+b)
def merkle(xs):
 a=[leaf(x) for x in xs]
 while len(a)>1:
  if len(a)%2:a.append(a[-1])
  a=[node(a[i],a[i+1]) for i in range(0,len(a),2)]
 return a[0]
class QMTO:
 def __init__(self,seed=b'ci'):
  self.seed=seed; self.g=0; self.hist=[]; self.audit=[]; self._new(b'\0'*32,'genesis')
 def s(self,g): return hmac.new(self.seed,b'GEN'+g.to_bytes(8,'big'),hashlib.sha256).digest()
 def _new(self,prev,reason):
  self.key=Lamport(self.s(self.g)); policy=merkle([f'pq:{self.g}'.encode(),f'rotate:{self.g}'.encode(),f'recovery:{self.g}'.encode(),f'next:{self.g+1}'.encode()]); nonce=H(self.s(self.g)+b'nonce'); self.prev=prev; self.policy=policy; self.commit=H(D_S+self.g.to_bytes(8,'big')+prev+self.key.root()+policy+nonce); self.audit.append(('start',self.g,self.commit.hex(),reason))
 def intent(self,tx): return H(D_I+self.g.to_bytes(8,'big')+self.commit+tx)
 def auth(self,tx):
  m=self.intent(tx); pub=self.key.pub(); sig=self.key.sign(m); return (self.g,self.commit,m,pub,sig)
 def verify(self,a,tx,current=True):
  g,c,m,pub,sig=a
  if current and g!=self.g:return False
  exp=H(D_I+g.to_bytes(8,'big')+c+tx)
  return hmac.compare_digest(m,exp) and Lamport.verify(pub,m,sig)
 def rotate(self,reason):
  old=self.commit; self.hist.append((self.g,old)); self.audit.append(('revoke',self.g,old.hex(),reason)); self.g+=1; self._new(old,reason)
class Guardian:
 def __init__(self,s): self.s=s; self.bad=deque(); self.dead=set(); self.alias=s.commit.hex()[:24]
 def rot(self,r): self.dead.add(self.alias); self.bad.clear(); self.s.rotate(r); self.alias=self.s.commit.hex()[:24]; return 'rotated'
 def acquire(self,alias,trusted=False,now=0,canary=False):
  if alias in self.dead:return 'decoy'
  if canary:return self.rot('canary')
  if trusted and alias==self.alias:return 'allow'
  while self.bad and self.bad[0]<now-10:self.bad.popleft()
  self.bad.append(now)
  return self.rot('threshold') if len(self.bad)>=3 else 'deny'
def proof():
 out=[]
 def ck(n,x): out.append((n,bool(x))); assert x,n
 s=QMTO(b'a'); tx=H(b'tx'); a=s.auth(tx); ck('valid',s.verify(a,tx)); ck('tamper',not s.verify(a,H(b'bad')))
 try:s.key.sign(b'x'); ok=False
 except RuntimeError:ok=True
 ck('one-time',ok)
 s=QMTO(b'b'); c=s.commit; s.rotate('x'); ck('chain',s.g==1 and s.prev==c)
 s=QMTO(b'c'); tx=H(b'x'); a=s.auth(tx); s.rotate('e'); ck('stale',not s.verify(a,tx))
 s=QMTO(b'd'); g=Guardian(s); ck('trusted',g.acquire(g.alias,True,1)=='allow'); old=g.alias; ck('deny1',g.acquire('bad',False,2)=='deny'); ck('deny2',g.acquire('bad',False,3)=='deny'); ck('threshold',g.acquire('bad',False,4)=='rotated'); ck('decoy',g.acquire(old,False,5)=='decoy')
 s=QMTO(b'e'); g=Guardian(s); ck('canary',g.acquire(g.alias,False,1,True)=='rotated')
 total=passed=0
 for L in range(1,5):
  for seq in itertools.product('TIC',repeat=L):
   total+=1; s=QMTO((''.join(seq)).encode()); g=Guardian(s); invalid=0; good=True
   for n,x in enumerate(seq,1):
    if x=='T': good &= g.acquire(g.alias,True,n)=='allow'
    elif x=='C': good &= g.acquire(g.alias,False,n,True)=='rotated'; invalid=0
    else:
     invalid+=1; r=g.acquire('bad',False,n); good &= r==('rotated' if invalid==3 else 'deny'); invalid=0 if invalid==3 else invalid
   passed+=bool(good)
 ck('sequence-sweep',passed==total==120)
 s=QMTO(b'z'); prev=s.commit
 for i in range(100): s.rotate(str(i)); ck(f'chain-{i}',s.prev==prev); prev=s.commit
 print(json.dumps({'proof_passed':len(out),'proof_total':len(out),'sequence_passed':passed,'sequence_total':total}))
def sh(*a): return subprocess.check_output(a,text=True).strip()
def btc(*a,wallet=False):
 cmd=['docker','compose','-f','qmto-ci/docker-compose.yml','exec','-T','bitcoind','bitcoin-cli','-regtest','-rpcuser=qmto','-rpcpassword=qmto-regtest-only']
 if wallet:cmd.append('-rpcwallet=qmto')
 cmd += list(a); return sh(*cmd)
def integration():
 btc('createwallet','qmto'); addr=btc('getnewaddress','','bech32m',wallet=True); btc('generatetoaddress','101',addr)
 s=QMTO(b'docker'); g=Guardian(s); c0=s.commit.hex()
 def anchor(c):
  raw=btc('createrawtransaction','[]',json.dumps([{'data':c}]),wallet=True); funded=json.loads(btc('fundrawtransaction',raw,wallet=True)); signed=json.loads(btc('signrawtransactionwithwallet',funded['hex'],wallet=True)); assert signed['complete']; return btc('sendrawtransaction',signed['hex'],wallet=True)
 t0=anchor(c0); btc('generatetoaddress','1',addr); tx=H(b'docker-spend'); a=s.auth(tx); g.acquire('x',False,1);g.acquire('x',False,2);g.acquire('x',False,3); assert s.g==1 and not s.verify(a,tx); c1=s.commit.hex(); t1=anchor(c1); btc('generatetoaddress','1',addr); height=json.loads(btc('getblockchaininfo'))['blocks']; assert height==103
 print(json.dumps({'integration':'PASS','height':height,'generation':s.g,'c0':c0,'c1':c1,'anchor0_txid':t0,'anchor1_txid':t1,'stale_rejected':True}))
if __name__=='__main__':
 {'proof':proof,'integration':integration}[sys.argv[1]]()
