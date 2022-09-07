#!/usr/bin/env python
from __future__ import print_function
import argparse
import sys
import socket
import random
import struct
import re
import json
from check_formula import *

import readline

answer,v,c = devide_table(sys.argv[1])
limit = int(sys.argv[2])
string = str(sys.argv[1])
string = string[17:]
if answer <= limit:
    file_clauses = open("data/formula_need/"+string,"w")
    file_clauses.close()
