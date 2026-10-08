import re, json, sys
BLOCK=r'(?:div|p|ul|ol|li|h[1-6]|section|details|pre|header|nav|footer|summary)'
PAT=re.compile(r'<(h1|h2|h3|h4|p|li|summary|span|div|a|b)((?:\s[^>]*)?)>((?:(?!<'+BLOCK+r'\b)(?!</?\1\b).)*?)</\1>', re.S)
def body_bounds(src):
    b=src.index('<body'); return b, len(src)
def mask_pre(src):
    # replace <pre>...</pre> with placeholders so nothing inside is translated
    pres=[]
    def r(m): pres.append(m.group(0)); return f'\x00PRE{len(pres)-1}\x00'
    return re.sub(r'<pre\b.*?</pre>', r, src, flags=re.S), pres
def segments(src):
    b,_=body_bounds(src); head,body=src[:b],src[b:]
    body,pres=mask_pre(body)
    segs=[]
    for m in PAT.finditer(body):
        inner=m.group(3)
        text=re.sub(r'<[^>]+>','',inner)
        if not re.search(r'[A-Za-z]',text): continue
        if '\x00PRE' in inner: continue
        segs.append(inner.strip())
    return segs
if __name__=='__main__':
    src=open(sys.argv[1],encoding='utf-8').read()
    segs=segments(src)
    seen=[];[seen.append(s) for s in segs if s not in seen]
    json.dump(seen,open(sys.argv[2],'w'),ensure_ascii=False,indent=0)
    print(len(segs),'segments',len(seen),'unique',sum(len(s) for s in seen),'chars')
