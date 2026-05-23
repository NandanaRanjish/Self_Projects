__IMPLEMENTATION LOGIC__

Building a custom data link and software protocol from scratch.
The underlying communication channel is basically a media intercepted with a lot of noise causing corruption and droppage of data, garbage bytes, delayed transmission, duplicate packets and unwanted packet modifications. 
We are to design a software that has to implemented upon this communication channel to ensure robust delivery of packets by defining a protocol that deals with packet formatting, error detection and proper receiving set up to ensure the delivered packets are received with full integrity.

*FRAMING OF PACKETS*

The radio will be transmitting endless stream of bytes without a proper packet structure. We have to first wrap the data in a proper envelope.
We define Start of Frame, End of Frame and Escape sequence(explanation given in code comments).

*ERROR DETECTION*

We append a mathematical fingerprint to the end of the packet, calculated from the packet's contents and attach it from the sender's end and is recalculated and verified at the receiver's end. 
Here, I am using CRC-8(cyclic redundancy check) that uses binary polynomial division to detect burst errors.

*HANDLING DROPS AND DUPLICATES*

I am using an automatic stop and request(ARQ) to handle drops. Station A sends one packet and starts a timer. It stops and waits. It will not send another data packet until Station B sends back a tiny ACK (Acknowledgment) packet. If ACK is not received it will retransmit the packet once the timer runs out.
ACK is not send in case an error is detected. If error is detected, the received packet is dropped and requires the sender to retransmit the message again.

This is when duplicates occur and required sequencing in both the data packet send and receiver's end to keep track of duplicates. I have tagged the packets alternately using 0s and 1s.

*FINITE STATE MACHINE IMPLEMENTED AT RECEIVER'S END*

FSM keeps track of the current state of the receiver in the memory.
State 0 (LOOKING_FOR_SOF): Ignore every incoming byte until you see 0x7E. When seen, switch to State 1.
State 1 (COLLECTING_DATA): Save incoming bytes into an array buffer. If you see the escape byte, handle it. If you see 0x7F (EOF), switch to State 2.
State 2 (VALIDATING): Check the CRC/Checksum. If valid, pass the data to the system and send an ACK. Switch back to State 0.

__FINAL PACKET STRUCTURE__
[SOF (1B)] | [Type (1B)] | [Seq (1B)] | [Len (1B)] | [Payload (Max 26B)] | [CRC8 (1B)] | [EOF (1B)]

(detailed code explanation added as comments in code)

