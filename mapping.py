#!/usr/bin/env python
# coding: utf-8

# In[7]:


import csv
import random

# possible values for ports, protocols, and tags
ports = range(1, 65536)  
protocols = ['tcp', 'udp', 'icmp']
tags = ['sv_P1', 'sv_P2', 'sv_P3', 'sv_P4', 'sv_P5', 'email', 'web', 'database', 'dns', 'ftp', 'vpn', 'snmp']

with open('lookup_table.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['dstport', 'protocol', 'tag'])

    # Generate 1200 random mappings
    for _ in range(1200):
        port = random.choice(ports)
        protocol = random.choice(protocols)
        tag = random.choice(tags)
        writer.writerow([port, protocol, tag])

print("Generated 1200 entries in 'lookup_table.csv'")


# In[8]:


from collections import defaultdict

# Function to load the lookup table from a CSV file
def load_lookup_table(lookup_table_file):
    lookup_table = {}
    with open(lookup_table_file, 'r') as f:
        next(f) 
        for line in f:
            dstport, protocol, tag = line.strip().split(',')
            key = (int(dstport), protocol.lower())
            lookup_table[key] = tag.lower()
    return lookup_table


# In[9]:


# Function to process flow logs and map them to tags based on the lookup table
def process_flow_logs(flow_log_file, lookup_table):
    tag_count = defaultdict(int)
    port_protocol_count = defaultdict(int)

    with open(flow_log_file, 'r') as f:
        for line_num, line in enumerate(f, start=1):
            fields = line.split()

           
            if len(fields) < 6:
                print(f"Skipping line {line_num}: Not enough fields. Content: {line.strip()}")
                continue
            
            try:
            
                dstport = int(fields[5])
                protocol = 'tcp' if fields[6] == '6' else 'udp'
                key = (dstport, protocol)
                
                # Look up the tag, default to 'untagged'
                tag = lookup_table.get(key, 'untagged')
                
                # Update counts for the tag and port/protocol combination
                tag_count[tag] += 1
                port_protocol_count[key] += 1
            except (ValueError, IndexError) as e:
                print(f"Error processing line {line_num}: {e}")
                continue  # Skip lines that raise errors

    return tag_count, port_protocol_count


# In[10]:


# Function to output to a file
def write_output(tag_count, port_protocol_count, output_file):
    with open(output_file, 'w') as f:
        #tag counts
        f.write("Tag Counts:\n")
        f.write("Tag,Count\n")
        for tag, count in tag_count.items():
            f.write(f"{tag},{count}\n")
        
        #port/protocol combination counts
        f.write("\nPort/Protocol Combination Counts:\n")
        f.write("Port,Protocol,Count\n")
        for (port, protocol), count in port_protocol_count.items():
            f.write(f"{port},{protocol},{count}\n")


# In[9]:


# Function to process flow logs and map them to tags based on the lookup table
def process_flow_logs(flow_log_file, lookup_table):
    tag_count = defaultdict(int)
    port_protocol_count = defaultdict(int)

    with open(flow_log_file, 'r') as f:
        for line_num, line in enumerate(f, start=1):
            fields = line.split()

           
            if len(fields) < 6:
                print(f"Skipping line {line_num}: Not enough fields. Content: {line.strip()}")
                continue
            
            try:
            
                dstport = int(fields[5])
                protocol = 'tcp' if fields[6] == '6' else 'udp'
                key = (dstport, protocol)
                
                # Look up the tag, default to 'untagged'
                tag = lookup_table.get(key, 'untagged')
                
                # Update counts for the tag and port/protocol combination
                tag_count[tag] += 1
                port_protocol_count[key] += 1
            except (ValueError, IndexError) as e:
                print(f"Error processing line {line_num}: {e}")
                continue  # Skip lines that raise errors

    return tag_count, port_protocol_count


# In[11]:


# Main function to load data, process logs, and generate output
def main():
    lookup_table_file = 'lookup_table.csv' 
    flow_log_file = 'flow_logs.txt'        
    output_file = 'output.txt'              

    # Load the lookup table
    lookup_table = load_lookup_table(lookup_table_file)
    
    # Process the flow logs and get the counts
    tag_count, port_protocol_count = process_flow_logs(flow_log_file, lookup_table)
    
    #results to the output file
    write_output(tag_count, port_protocol_count, output_file)


if __name__ == '__main__':
    main()


# In[ ]:




