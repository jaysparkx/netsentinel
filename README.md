# NetSentinel

Hybrid machine-learning intrusion detection system for network traffic.

A supervised classifier recognises known attacks (DoS, Probe, R2L, U2R), and an autoencoder trained only on normal traffic flags connections that look unusual, so attacks the classifier never saw still raise an alert. Tested on NSL-KDD, CIC-IDS2017 and packets captured on our own machine, with a small website for results, pcap analysis and live detection.

Setup and usage: [`run.txt`](run.txt). Documentation: [`docs/`](docs/00_start_here.md).
