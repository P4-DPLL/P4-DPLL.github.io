#!/usr/bin/env python
from __future__ import print_function
import argparse
import sys
import socket
import random
import struct
import re
import json
from devide import *
from generate_entry import *

from scapy.all import sendp, send, srp1, sniff
from scapy.all import Packet, hexdump
from scapy.all import Ether, StrFixedLenField, XByteField, IntField, BitField
from scapy.all import bind_layers
import readline

string = str(sys.argv[1])
#print(string)
string = string[17:]
string = string[:-4]
devide_table(int(string))
generate_entry()