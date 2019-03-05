#!/usr/bin/env python

# This utility computes shamir shares of a provided secret
#
# USAGE: ./shamir-share.py numShareholders threshold secret [curve-name]

# Imports
from sys import argv
from sys import exit
from random import SystemRandom

################################################################################################
# Elliptic Curve Functions
################################################################################################

class curve:
  def __init__(self, a, b, p, r):
    self.a = a
    self.b = b
    self.p = p
    self.r = r

  def mod_inv(self, x):
    return pow(x, self.p - 2, self.p)

  def mod_inv_order(self, x):
    return pow(x, self.r - 2, self.r)

  def add_points(self, p, q):
    s = (p.y - q.y) * self.mod_inv(p.x - q.x) % self.p
    x = (s*s - (p.x + q.x)) % self.p
    y = (s * (p.x - x) - p.y) % self.p
    return point(x, y)

  def point_double(self, p):
    s = (3 * p.x * p.x + self.a) * self.mod_inv(2 * p.y) % self.p
    x = (s*s - 2 * p.x) % self.p
    y = (s * (p.x - x) - p.y) % self.p
    return point(x, y)

  def multiply_point(self, c, n):
    r = None
    cpow2 = c
    while (n > 0):
      if (n & 1 == 1):
        if (r is None):
          r = cpow2
        else:
          r = self.add_points(r, cpow2)
      n = (n >> 1)
      cpow2 = self.point_double(cpow2)
    return r

class point:
  def __init__(self, x, y):
    self.x = x
    self.y = y

  def __eq__(self, other):
    if isinstance(other, self.__class__):
      return self.__dict__ == other.__dict__
    else:
      return False

  def __ne__(self, other):
    return not self.__eq__(other)

  def __str__(self):
    return "(" + str(self.x) + ", " + str(self.y) + ")"



################################################################################################
# Elliptic Curves
################################################################################################

# NIST Curve P-192:
p = 6277101735386680763835789423207666416083908700390324961279
r = 6277101735386680763835789423176059013767194773182842284081
a = 6277101735386680763835789423207666416083908700390324961276
b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
secp192r1 = curve(a, b, p, r)

# NIST Curve P-256 (secp256r1)
p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
r = 115792089210356248762697446949407573529996955224135760342422259061068512044369
a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
secp256r1 = curve(a, b, p, r)

# NIST Curve P-521 (secp521r1)
p = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151
r = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449
a = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148
b = 1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984
secp521r1 = curve(a, b, p, r)

curves = {}
curves['secp192r1'] = secp192r1
curves['secp256r1'] = secp256r1
curves['secp521r1'] = secp521r1

################################################################################################
# Shamir Functions
################################################################################################

def generate_coefficients(secret, threshold, curve):
  coefficients = []
  coefficients.append(secret)
  for i in range(1, threshold):
    r = SystemRandom().randint(1, curve.r-1) 
    coefficients.append(r)
  return coefficients

def evaluate_polynomial(coefficients, evaluation_coordinate, curve):
  r = curve.r
  y = 0
  for i in range(len(coefficients)):
    # Compute sum of: a_i * x_i^i
    y += coefficients[i] * pow(evaluation_coordinate, i, r)
  return (y % r)

def compute_shares(coefficients, num_shares, curve):
  shares = []
  for i in range(1, num_shares+1):
    shares.append((i, evaluate_polynomial(coefficients, i, curve)))
  return shares

################################################################################################
# Main
################################################################################################

command = argv[0]

g = point(28180968562641497067278236429211977508043174361740661643726011666495902464602, 71059786474789917358912012681919876999588411700471748715771920653989729645170)

curve = secp256r1
if len(argv) == 5:
  curve_name = argv[4]
  if (curve_name in curves):
    curve = curves[curve_name]
  else:
    print "Unknown curve name: " + curve_name
    print "Known curves: "
    for key, value in curves.iteritems() :
      print "  " + key
    exit(1)

# This computes shamir shares of a provided secret
if len(argv) < 4:
  print "USAGE: " + command + " numShares threshold secret [curve-name]"
else:
  num_shares = int(argv[1])
  threshold = int(argv[2])
  secret = int(argv[3])
  coefficients = generate_coefficients(secret, threshold, curve)
  shares = compute_shares(coefficients, num_shares, curve)
  #print coefficients
  print "Shares:"
  for share in shares:
    print share
  print "Secret Public Key:"
  print curve.multiply_point(g, secret)

