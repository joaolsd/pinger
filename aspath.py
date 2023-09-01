#!/usr/bin/env python3
import sys
import ipaddress
from collections import defaultdict
import subprocess

MAX_HOPS = 32

def init_list():
  return [-1] * MAX_HOPS

# Launch originas subprocess
p = subprocess.Popen(["/usr/local/bin/originas"],
          stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize = 0, text = True)

num_servers=len(sys.argv)-1
print("num servers:", num_servers)
iter=0
path_valid = [defaultdict(init_list) for i in range(num_servers)]
path_invalid = [defaultdict(init_list) for i in range(num_servers)]

debug_ip = ipaddress.ip_address("217.140.64.0")

for host in sys.argv[1:]:
  valid_input_file = "rpki4-valid-"+host+"-test.log"
  invalid_input_file = "rpki4-invalid-"+host+"-test.log"
  # open and read file with (ROA) valid source address yarrp trace
  # every ASN should show up here as this are just normal packets
  # file line format is
  # 93.95.65.0,10.75.1.113,4,TE,F
  # IP address of target, IP address of host generating ICMP, hop count, ICMP code (TE=time exceeded), unused
  count = 0
  with (open(valid_input_file)) as f:
    print("reading file:"+valid_input_file)
    Lines = f.readlines()
    for line in Lines:
      count += 1
      line_split = line.split(',')
      try:
        target_ip = ipaddress.ip_address(line_split[0])
      except Exception as e:
        print("line:",count,"IP:",line_split[0])
        continue
      hop_address = line_split[1]
      hop = int(line_split[2])

      # put together AS path for each target address
      p.stdin.write(str(target_ip)+"\n") # Get ASN for target address on this line
      addr_asn = p.stdout.readline()
      addr,target_asn = addr_asn.strip().split(',')
      target_asn=int(target_asn)

      path_valid[iter][target_ip][0] = target_asn # Store ASN of target IP at hop 0

      p.stdin.write(hop_address+"\n") # Get ASN for hop address on this line
      addr_asn = p.stdout.readline()
      addr,hop_asn = addr_asn.strip().split(',')
      hop_asn=int(hop_asn)
      try:
        path_valid[iter][target_ip][hop] = hop_asn
        if (debug_ip == target_ip):
          print(host, "valid", target_ip, target_asn, hop, addr, hop_asn)
      except IndexError:
        # print("TTL/hop too big:", hop)
        # I guess some packets get mangled, badly, by middle boxes.
        continue
  print("Finished reading valid source yarrp trace lines: ", count)

  count= 0
  # open and read file with (ROA) invalid source address in the trace
  with (open(invalid_input_file)) as f:
    print("reading file:"+invalid_input_file)
    Lines = f.readlines()
    for line in Lines:
      count += 1
      line_split = line.split(',')
      try:
        target_ip = ipaddress.ip_address(line_split[0])
      except Exception as e:
        print("line:",count,"IP:",line_split[0])
        continue
      hop_address = line_split[1]
      hop = int(line_split[2])
      # put together AS path for each target address
      p.stdin.write(str(target_ip)+"\n") # Get ASN for target address on this line
      addr_asn = p.stdout.readline()
      addr,target_asn = addr_asn.strip().split(',')
      target_asn=int(target_asn)
      path_invalid[iter][target_ip][0] = target_asn # Store ASN of target IP at hop 0

      p.stdin.write(hop_address+"\n") # Get ASN for hop address on this line
      addr_asn = p.stdout.readline()
      addr,hop_asn = addr_asn.strip().split(',')
      hop_asn=int(hop_asn)
      try:
        path_invalid[iter][target_ip][hop] = hop_asn
        if (debug_ip == target_ip):
          print(host, "invalid", target_ip, target_asn, hop, addr, hop_asn)
      except IndexError:
        # print("TTL/hop too big:", hop)
        # I guess some packets get mangled, badly, by middle boxes.
        continue
  print("Finished reading invalid source yarrp trace lines: ", count)
  iter+=1 # End of server loop
  print("iter:", iter)

# Write out results (AS PATH to target address from ROA valid and ROA invalid addresses)
with open("as_paths.txt", "w") as f:
  print("# AS PATH to target address from valid and invalid source", file=f)
  for target_ip in path_valid[0]:
    for iter in range(num_servers):
      target_ip_str = str(target_ip)
      print("{:<15}".format(target_ip_str)+"@"+sys.argv[1+iter]+":"+",".join("{:6d}".format(a) for a in path_valid[iter][target_ip]), file=f)
      print(' '*21,','.join("{:6d}".format(a) for a in path_invalid[iter][target_ip]), file=f)
      # print(target_ip_str+":",path_valid[target_ip], file = f)
      # print(len(target_ip_str)*' '+' ',path_invalid[target_ip], file = f)

