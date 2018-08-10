# pross
Proactive Secret Sharing and Distributed Key Generation

## Overview

This project implements the Proactive Secret Sharing (PROSS) protocol, first described in 1995 by Amir Herzberg, Stanislaw Jarecki, Hugo Krawczyk, and Moti Yung in their paper "Proactive Secret Sharing Or: How to Cope with Perpetual Leakage": 
( https://pdfs.semanticscholar.org/d367/55ccc7902e3e09db5c82897401ab0877df3d.pdf )

Additionally, this project implements the Distributed Key Generation (DKG) protocol, first described in 1999 by Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin in their 1999 paper "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems":
( https://groups.csail.mit.edu/cis/pubs/stasio/vss.ps.gz )

Both of these protocols depend on an atomic broadcast channel. In the real world of asynchronrouns networks and distributed systems the idealization of an atomic broadcast channel must be built on top of a distributed, byzantine-fault-tolerant, consensus system.  Therefore network communication among the component servers of the PROSS and DKG systems uses Byzantine Fault Tolerant (BFT) State Machine Replication (SMR) based on the BFT-SMaRt library:
( https://github.com/bft-smart/library )

## Deploying

TODO: Write deployment instructions

## Operations

TODO: Provide examples of performing various supported operations
