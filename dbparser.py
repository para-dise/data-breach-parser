from statistics import mode
from statistics import median
import enchant #pyEnchant
engdict = enchant.Dict("en_US")

class doubleenter(Exception):
    pass

fp = input("Path: ")
spby = None
oldspby = None

def Average(lst): 
    return sum(lst) / len(lst) 


i1 = 0
i2 = 0
i3 = 0

avgcombo = []
avgcomma = []
avgvline = []

with open(fp, "r") as f:
  for counter, line in enumerate(f):
    l = line.strip("\n")
    splitby_combo = l.count(":")
    i1 += splitby_combo
    if splitby_combo != 0:
      avgcombo.append(splitby_combo)
    splitby_comma = l.count(",")
    i2 += splitby_comma
    if splitby_comma != 0:
      avgcomma.append(splitby_comma)
    splitby_vline = l.count("|")
    if splitby_vline != 0:
      avgvline.append(splitby_vline)
    i3 += splitby_vline
    d = {':':splitby_combo, ',':splitby_comma, '|':splitby_vline}
    splitby = max(d.items(), key=lambda i: i[1])
    if counter != 0:
      if spby != splitby[0]:
        if oldspby == splitby[0]:
          print("\33[34m[DBParser] \u001b[32mSetting back to old split char... " + str(splitby[0] + " on line " + str(counter)))
        else:
          print("\33[34m[DBParser] \033[33mSplitting by different character " + str(splitby[0]) + " on line " + str(counter))
    oldspby = spby
    spby = splitby[0]
print("\33[34m[DBParser] \u001b[32mFound {} occourrences of :".format(str(i1)))
print("\33[34m[DBParser] \u001b[32mFound {} occourrences of ,".format(str(i2)))
print("\33[34m[DBParser] \u001b[32mFound {} occourrences of |".format(str(i3)))

ac = None
splitchar = None

if len(avgcombo) > len(avgcomma) and len(avgcombo) > len(avgvline):
  ac = median(avgcombo)
  splitchar = ":"
if len(avgcomma) > len(avgcombo) and len(avgcomma) > len(avgvline):
  ac = median(avgcomma)
  splitchar = ","
if len(avgvline) > len(avgcomma) and len(avgvline) > len(avgcombo):
  ac = median(avgvline)
  splitchar = "|"

print("\33[34m[DBParser] \u001b[32mSplit char set to " + splitchar)
splitcount = int(ac)
print("\33[34m[DBParser] \u001b[32mSplit count set to " + str(splitcount + 1))

narr = []

with open(fp, "r", encoding='utf-8', errors='ignore') as f:
  for line in f:
    l = line.strip("\n")
    ln = l.split(splitchar, splitcount)
    if len(ln) == splitcount + 1:
      narr.append(ln)
    else:
      pass
      #print(len(ln))

emailposarr = []
bcryptarr = []
md5arr = []
sha256arr = []
usernamearr = []
import re

for enumc, arr in enumerate(narr):
   for c, v in enumerate(arr):
     if len(v) > 100:
       print("\33[34m[DBParser] \u001b[32mLine too long -> \33[31m" + v)
       continue
     if re.match(r"<\s*a[^>]*>(.*?)<\s*/\s*a>", v):
       print("\33[34m[DBParser] \u001b[32mHTML Detected -> \33[31m" + v)
       continue
     if re.match(r"[^@]+@[^@]+\.[^@]+", v):
       print("\33[34m[DBParser] \u001b[32mE-Mail detected -> \33[31m" + v)
       emailposarr.append(c)
       continue
     if re.match(r"^\$2[ayb]\$.{56}$", v):
       print("\33[34m[DBParser] \u001b[32mHash detected [BCrypt] -> \33[31m" + v)
       bcryptarr.append(c)
       continue
     if re.match(r"^[a-f0-9]{32}$", v):
       print("\33[34m[DBParser] \u001b[32mHash detected [MD5]-> \33[31m" + v)
       md5arr.append(c)
       continue
     if re.match(r"[A-Fa-f0-9]{64}", v):
       print("\33[34m[DBParser] \u001b[32mHash detected [SHA256]-> \33[31m" + v)
       sha256arr.append(c)
       continue
     if re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", v):
       print("\33[34m[DBParser] \u001b[32mIP address detected -> \33[31m" + v)
       sha256arr.append(c)
       continue
     gchars = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
     wordtocheck = v
     for char in gchars:
       wordtocheck = wordtocheck.strip(char)
     if len(wordtocheck) > 0:
       if engdict.suggest(wordtocheck) != []:
         try:
           for word in engdict.suggest(wordtocheck):
             if word.lower() in wordtocheck.lower():
               print("\33[34m[DBParser] \u001b[32mUsername detected -> \33[31m" + v)
               usernamearr.append(c)
               raise doubleenter("Entered twice")
         except doubleenter:
           pass
   if enumc == 250:
     break 
