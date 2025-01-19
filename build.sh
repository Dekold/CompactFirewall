#!/bin/bash
cd src
sudo make clean
sudo make
cp My_firewall.ko ../My_firewall.ko
