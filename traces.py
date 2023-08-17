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
merge_drop_as = dict()
merge_all_asn = dict()
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

      # put together list of all ASN seen
      p.stdin.write(str(target_ip)+"\n") # Get ASN for target address on this line
      addr_asn = p.stdout.readline()
      addr,asn = addr_asn.strip().split(',')
      asn=int(asn)
      all_asn.add(asn)
      if asn not in addr_seen_by_asn:
        addr_seen_by_asn[asn]=set()
      addr_seen_by_asn[asn].add(addr)
      p.stdin.write(hop_address+"\n") # Get ASN for hop address on this line
      addr_asn = p.stdout.readline()
      addr,asn = addr_asn.strip().split(',')
      asn=int(asn)
      if asn not in addr_seen_by_asn:
        addr_seen_by_asn[asn]=set()
      addr_seen_by_asn[asn].add(addr)
      all_asn.add(asn)

      try:
        target_valid[target_ip][hop] = ipaddress.ip_address(hop_address)
      except IndexError:
        print("TTL/hop too big:", hop)
        # I guess some packets get mangled, badly, by middle boxes.
        continue
  print("Finished reading valid source yarrp trace lines: ", count)

  with (open("debug.txt","w")) as df:
    for target in sorted(target_valid):
      print(str(target), target_valid[target], file=df)
    print ("##############################", file=df)

  count= 0
  # open and read file with (ROA) invalid source address in the trace
  with (open(invalid_input_file)) as f:
    Lines = f.readlines()
    for line in Lines:
        count += 1
        line_split = line.split(',')
        target_ip = ipaddress.ip_address(line_split[0])
        hop_address = line_split[1]
        hop = int(line_split[2])
        # Any ASN seen in this trace is not validating
        p.stdin.write(hop_address+"\n") # Get ASN for hop address on this line
        addr_asn = p.stdout.readline()
        addr,asn = addr_asn.strip().split(',')
        asn=int(asn)
        non_validating_as.add(asn)
        # p.stdin.write(str(target_ip)+"\n") # Get ASN for target address on this line
        # addr_asn = p.stdout.readline()
        # addr,asn = addr_asn.strip().split(',')
        # non_validating_as.add(int(asn)) 
        try:
          target_invalid[target_ip][hop] = ipaddress.ip_address(hop_address)
        except IndexError:
          print("TTL/hop too big:", hop)
          continue
  print("Finished reading invalid source yarrp trace lines: ", count)

  validating_as = set(all_asn).difference(non_validating_as)

  # merge this host data into the full set
  for asn in all_asn:
    if asn not in merge_all_asn:
      merge_all_asn[asn]= [0]*num_servers
    merge_all_asn[asn][iter] = 1 # is the asn seen in the path at server rpki($iter)
  for asn in non_validating_as:
    if asn not in merge_drop_as:
      merge_drop_as[asn] = list()
      for i in range(0,num_servers):
        merge_drop_as[asn].append([0,0])
    merge_drop_as[asn][iter][0] += 1
  for asn in validating_as:
    if asn not in merge_drop_as:
      merge_drop_as[asn] = list()
      for i in range(0,num_servers):
        merge_drop_as[asn].append([0,0])
    merge_drop_as[asn][iter][1] += 1

  # Dump arrays
  with (open("debug_ip"+host+".txt", "w")) as f:
    for target in sorted(target_valid):
      print(str(target),":", file=f)
      for hop,hop_address in enumerate(target_valid[target]):
        if hop_address is None:
          continue
        print(hop, hop_address, file=f)
    
    print("#########################################", file=f)
    for target in sorted(target_invalid):
      print(str(target),":", file=f)
      for hop,hop_address in enumerate(target_invalid[target]):
        if hop_address is None:
          continue
        print("  ",hop, hop_address, file=f)

  with (open("validating-"+host+".txt", "w")) as f:
    print("#########################################", file=f)
    print("List of validating ASN", file = f)
    print(','.join(str(a) for a in sorted(validating_as)), file=f)
    print("#########################################", file=f)
    print("List of non validating ASN ", file = f)
    print(','.join(str(a) for a in sorted(non_validating_as)), file=f)
  iter+=1 # End of server loop
  print("iter:", iter)

with open("addresses_per_asn.txt", "w") as f:
  print("# List of addresses seen in traces for each ASN", file=f)
  for asn in sorted(addr_seen_by_asn):
    if (asn==0):
      continue
    print(asn, addr_seen_by_asn[asn], file=f)

with(open("validating-all.txt", "w")) as f:
  print("# rpki2=singapore, rpki3=frankfurt, rpki4=LA, rpki5=Mumbai", file =f)
  print("# ASN, server1, server2,...", file = f)
  print("# For each server (0..4): ",file=f)
  print("# For each pair, first value indicates not validating, second indicates (possibly) validating", file = f)
  for asn in sorted(merge_drop_as):
    print(asn, "[",sum(merge_drop_as[asn][i][0] for i in range(num_servers)),",",
      sum(merge_drop_as[asn][i][1] for i in range(num_servers)),"]", merge_drop_as[asn], file = f)

