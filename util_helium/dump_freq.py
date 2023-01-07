#!/usr/bin/env python3
import sys
import json
import re

def calc_freq(block, radio_freq):
    freq = radio_freq[int(block['radio'])]
    freq += int(block['if'])
    return freq

b = sys.stdin.read()
b = re.sub('/\*.*\*/', '', b)
d = json.loads(b)
radio_freq = {}

conf = d['SX130x_conf']

radio_freq[0] = int(conf['radio_0']['freq'])
radio_freq[1] = int(conf['radio_1']['freq'])

frequencies = []

for channel in range(8):
    name = 'chan_multiSF_%d' % channel
    block = conf[name]

    if block['enable']:
        frequencies.append(calc_freq(block, radio_freq))

lora_std = 'None'
fsk = 'None'

block = conf['chan_Lora_std']
if block["enable"]:
    f = calc_freq(block, radio_freq)
    bw = int(block['bandwidth'])
    sf = int(block['spread_factor'])
    lora_std = f"{f/1e6:g} / SF{sf:d}BW{int(bw/1e3):d}"

block = conf['chan_FSK']
if block["enable"]:
    f = calc_freq(block, radio_freq)
    bw = int(block['bandwidth'])
    datarate = int(block['datarate'])
    fsk = f"{f/1e6:g} / DR{int(datarate/1e3):d}BW{int(bw/1e3):d}"

print('\n'.join('%g' % (x / 1e6) for x in sorted(frequencies)))
print('chan_Lora_std:', lora_std)
print('chan_FSK     :', fsk)
