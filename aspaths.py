#!/usr/bin/env python3
import sys
import ipaddress
from collections import defaultdict
import subprocess

MAX_HOPS = 32

def init_list():
  return [None] * MAX_HOPS

# Launch originas subprocess
p = subprocess.Popen(["/usr/local/bin/originas"],
          stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize = 0, text = True)

num_servers=len(sys.argv)-1
print("num servers:", num_servers)
aspath = dict()
sum_aspath = dict()
addr_seen_by_asn=dict()
iter=0
for host in sys.argv[1:]:
  valid_input_file = "rpki4-valid-"+host+"-test.log"
  invalid_input_file = "rpki4-invalid-"+host+"-test.log"
  target_valid = defaultdict(init_list)
  target_invalid = defaultdict(init_list)
  all_asn = set()
  validating_as=set()
  non_validating_as=set()
  # open and read file with (ROA) valid source address yarrp trace
  # every ASN should show up here as this are just normal packets
  # file line format is
  # 93.95.65.0,10.75.1.113,4,TE,F
  # IP address of target, IP address of host generating ICMP, hop count, ICMP code (TE=time exceeded), unused
  count = 0
  with (open(valid_input_file)) as f:
    Lines = f.readlines()
    for line in Lines:
      count += 1
      line_split = line.split(',')
      target_ip = ipaddress.ip_address(line_split[0])
      hop_address = line_split[1]
      hop = int(line_split[2])
      if (hop > MAX_HOPS):
        print("TTL/hop too big:", hop)
        continue

      # put together list of all ASN seen
      p.stdin.write(str(target_ip)+"\n") # Get ASN for target address on this line
      addr_asn = p.stdout.readline()
      addr,asn = addr_asn.strip().split(',')
      asn=int(asn)
      all_asn.add(asn)
      if asn not in aspath:
        aspath[asn] = [-1] * MAX_HOPS

      if asn not in addr_seen_by_asn:
        addr_seen_by_asn[asn]=set()
      addr_seen_by_asn[asn].add(addr)
      p.stdin.write(hop_address+"\n") # Get ASN for hop address on this line
      addr_asn = p.stdout.readline()
      addr,asn_hop = addr_asn.strip().split(',')
      asn_hop=int(asn_hop)
      if asn_hop not in addr_seen_by_asn:
        addr_seen_by_asn[asn_hop]=set()
      addr_seen_by_asn[asn_hop].add(addr)
      all_asn.add(asn_hop)
      aspath[asn][hop] = asn_hop

  print("Finished reading valid source yarrp trace lines: ", count)

  # with (open("debug.txt","w")) as df:
  #   for target in sorted(target_valid):
  #     print(str(target), target_valid[target], file=df)
  #   print ("##############################", file=df)

  # drop contiguous repetitions from ASPATH
  for asn in aspath:
    # Trim the list from the end side
    i = MAX_HOPS-1
    # print("Initial")
    # print(asn,aspath[asn])
    while (aspath[asn][i] == -1):
      aspath[asn].pop()
      i -= 1

    while (True):
      duplicates = 0
      cur_aspath = aspath[asn]
      # print("right trimmed", cur_aspath)
      summ_aspath = list()
      hop = 1 
      while (hop < len(cur_aspath)):
        # print("hop",hop)
        if cur_aspath[hop] != 0 and cur_aspath[hop] != -1:
          summ_aspath.append(cur_aspath[hop])
        if (hop+1 < len(cur_aspath)):
          if (cur_aspath[hop+1] == cur_aspath[hop]):
            hop += 1
            duplicates = 1
            # print("rep or 0", hop)
        hop += 1
      aspath[asn] = summ_aspath
      if duplicates == 0:
        break
    # print("contiguous repetitions removed", summ_aspath)

    # Loops? ECMP?
    # cur_aspath = aspath[asn]
    # noloop_aspath = [cur_aspath[0]]
    # hop = 1
    # while (hop < len(cur_aspath)):
    #   try:
    #     n = cur_aspath[1,cur_aspath[hop-1]].index(cur_aspath[hop]) # find if this AS has already appeared (raise exception if not) and is so return its index in the ASPATH
    #     # print("found repeated patern at index",n, cur_aspath[n:hop-1])
    #     repetition = len(cur_aspath[n:hop-1]) # elements between original instance of current AS and the current AS path element
    #     del noloop_aspath[-repetition:]
    #   except:
    #     noloop_aspath.append(cur_aspath[hop])
    #     # print("added to path", noloop_aspath)
    #   hop += 1
    # aspath[asn] = noloop_aspath

  # generate per target ASPATH from data
  with (open("summ_aspath.csv","w")) as f:
    for asn in sorted(aspath):
      print(asn, end="", file=f)
      for hop in range(1,len(aspath[asn])):
        print(","+str(aspath[asn][hop]), end="", file=f)
      print(file=f)