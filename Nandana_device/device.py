import random
import time

class CommunicationProtocol:
    # Declaring stream based framing to define clear packet boundaries and control characters
    SOF = 0x7E  # Start of Frame
    EOF = 0x7F  # End of Frame
    ESC = 0x7D  # Escape Byte
# If the data contains frame bytes, 0x7D is placed in front of them so the receiver doesn't mistake them for true boundaries.

    # Packet Types
    TYPE_DATA = 0x01 #data packet type that contains the actual telemetry payload
    TYPE_ACK  = 0x02 #for confirming successful receiving of a packet

    # Parser State Machine States
    STATE_LOOKING_FOR_SOF = 0
    STATE_PROCESSING      = 1
    STATE_ESCAPED         = 2
    #different states to manage the parsing of incoming bytes (FSM)
    # includes recognising the start of the packet, collecting data and validating it

    def __init__(self, device_id): #initial function running on any machine
        self.device_id = device_id
        
        # Memory Budget Tracking (Strictly under 256 Bytes)
        # rx_buffer: max 32 bytes (32 bytes)
        # rx_state, tx_seq, expected_rx_seq: primitive integers (3 bytes)
        # total active memory allocation state <= ~35 bytes
        self.rx_buffer = bytearray() #dynamic temporary array for storage of all bytes until a packet is received
        self.rx_state = self.STATE_LOOKING_FOR_SOF #sets initial state to look for an SOF
        
        self.tx_seq = 0           # Outbound sequence number tracker (0 or 1) to look for duplicates
        self.expected_rx_seq = 0  # Inbound sequence number tracker expected (0 or 1)
        #Tracks the sequence bit the device expects to see on the next incoming packet.
        
# FOR ERROR CHECKING USING CRC-8 
    @staticmethod
    def calculate_crc8(data: bytes) -> int:
        #Calculates a robust 8-bit Cyclic Redundancy Check (CRC-8-CCITT)
        crc = 0x00
        for byte in data: #processes the data byte by byte
            crc ^= byte
            for _ in range(8): #process each bit in the byte
                if crc & 0x80:
                    crc = (crc << 1) ^ 0x07  # Polynomial: x^8 + x^2 + x + 1
                else:
                    crc <<= 1
                crc &= 0xFF
        return crc

#TRANSMISSION FORMATTING
    def serialize_packet(self, packet_type: int, seq_num: int, payload: bytes) -> bytes:
        # this takes raw data and bundles it into a serialized frame(authenticated packet)
    
        #structure: [SOF] [TYPE] [SEQ] [LEN] [PAYLOAD...] [CRC8] [EOF]
        
        # 1. Assemble un-framed raw body
        header = bytes([packet_type, seq_num, len(payload)]) #creates a 3 byte header with message type, sequence id and length of the payload
        raw_body = header + payload #combines the header and the payload to create the raw body of the packet
        crc = self.calculate_crc8(raw_body) #calculates the crc-8 code across the header and the payload
        unframed_packet = raw_body + bytes([crc]) #appends the single byte checksum to the end of the raw body

        # 2. Apply byte stuffing over the body to prevent marker collision
        stuffed_body = bytearray()
        for byte in unframed_packet:
            if byte in (self.SOF, self.EOF, self.ESC):
                stuffed_body.append(self.ESC)
                stuffed_body.append(byte ^ 0x20)  # Standard bit inversion escape modification
            else:
                stuffed_body.append(byte)
                #Checks if a data byte matches one of our structural flags
                #If it matches, we insert an escape byte (0x7D) ahead of it
                #Modifies the original byte value using an XOR inversion so it is no longer mistaken for a boundary marker

        # 3. Wrap with clear boundaries
        return bytes([self.SOF]) + stuffed_body + bytes([self.EOF])
    
    #THE RECEIVER FINITE STATE MACHINE IMPEMENTATION
    def process_incoming_byte_stream(self, stream: bytes):
       
        #Processes a raw, arbitrary chunk of incoming bytes.
        #Implemented via a strict single-byte Finite State Machine (FSM).
        
        valid_packets_extracted = []

        for byte in stream: #processes the stream sequentially, handling single bytes as they arrive
            if self.rx_state == self.STATE_LOOKING_FOR_SOF:
                if byte == self.SOF:
                    self.rx_buffer.clear()
                    self.rx_state = self.STATE_PROCESSING
                    #clears out any old buffer noise and switches to STATE_PROCESSING

            elif self.rx_state == self.STATE_PROCESSING:
                if byte == self.SOF:
                    # Spurious duplicate SOF encountered, reset buffer window cleanly
                    self.rx_buffer.clear()
                elif byte == self.EOF:
                    # End boundary reached! Attempt execution validation
                    validated_packet = self._validate_and_parse_buffer() #Extracts the content and checks for errors
                    if validated_packet:
                        valid_packets_extracted.append(validated_packet)
                    self.rx_state = self.STATE_LOOKING_FOR_SOF
                elif byte == self.ESC:
                    # Escape control marker found, drop it and prepare to modify next byte
                    self.rx_state = self.STATE_ESCAPED
                else:
                    # Enforce the 32-byte packet maximum limit defensively
                    if len(self.rx_buffer) < 32:
                        self.rx_buffer.append(byte)
                    else:
                        # Packet exceeded max allowed size; clear and recover
                        self.rx_state = self.STATE_LOOKING_FOR_SOF

            elif self.rx_state == self.STATE_ESCAPED:
                # Restore original stuffed literal byte values
                original_byte = byte ^ 0x20 #Reverts the escaped data byte back to its true original value
                if len(self.rx_buffer) < 32: #prevents memory overflow
                    self.rx_buffer.append(original_byte)
                    self.rx_state = self.STATE_PROCESSING
                else:
                    self.rx_state = self.STATE_LOOKING_FOR_SOF

        return valid_packets_extracted
    
    #INNER PACKET VERIFICATION AND PARSING    
    def _validate_and_parse_buffer(self):
        if len(self.rx_buffer) < 4:  # Minimum valid size: TYPE(1) + SEQ(1) + LEN(1) + CRC(1)
            return None

        # Extract the trailing CRC byte
        received_body = bytes(self.rx_buffer[:-1]) #Separates the main body from the trailing check byte.
        received_crc = self.rx_buffer[-1]

        # if the calculated CRC does not match the received CRC, we know the packet is corrupted and we drop it
        if self.calculate_crc8(received_body) != received_crc:
            print(f"[{self.device_id}] Internal Drop: Packet failed CRC check (Corrupted).")
            return None

        p_type = received_body[0]
        p_seq = received_body[1]
        p_len = received_body[2]
        payload = received_body[3:3+p_len]

        # Handle Acknowledgment matching
        if p_type == self.TYPE_ACK:
            return {"type": "ACK", "seq": p_seq, "payload": None}

        # Handle Data and process sequence checks to ignore duplicates
        if p_type == self.TYPE_DATA:
            if p_seq == self.expected_rx_seq:
                # New expected data arrived successfully
                self.expected_rx_seq = 1 - self.expected_rx_seq  # alternates the expected sequence bit
                return {"type": "DATA", "seq": p_seq, "payload": payload}
            else:
                # Duplicate transmission detected due to a dropped ACK link
                print(f"[{self.device_id}] Internal Warning: Detected duplicate packet (Seq {p_seq}). Dropping duplicate but returning ACK forcing function.")
                return {"type": "DUPLICATE", "seq": p_seq, "payload": payload}

        return None
        
        # timeout and retransmission functino for the sender side of the protocol incase the sender does not receive an ACK
    def send_packet_with_retry(self, payload: bytes, transport_channel, timeout_seconds: float = 2.0, max_retries: int = 5):
        
        #Handles the Stop-and-Wait ARQ loop. 
        #Sets a timer, transmits data, and handles retransmission if a timeout occurs.
        
        # 1. Serialize the message using our current outbound sequence number tracker
        serialized_packet = self.serialize_packet(self.TYPE_DATA, self.tx_seq, payload)
        
        retries = 0
        while retries < max_retries:
            print(f"\n[{self.device_id}] ---> Sending Packet (Seq: {self.tx_seq}), Attempt {retries + 1}")
            
            # 2. Transmit the raw bytes over the physical/simulated channel
            transport_channel.write(serialized_packet)
            
            # 3. SET THE TIMER: Record the start time using time.time()
            start_time = time.time()
            ack_received = False
            
            # 4. Wait and listen for the ACK until the timeout period expires
            while (time.time() - start_time) < timeout_seconds:
                # Read whatever bytes have arrived on the radio channel
                incoming_bytes = transport_channel.read()
                
                if incoming_bytes:
                    # Feed bytes directly into your single-byte Finite State Machine (FSM)
                    parsed_events = self.process_incoming_byte_stream(incoming_bytes)
                    
                    for event in parsed_events:
                        # 5. Check if the parsed packet is a valid ACK matching our transmitted sequence number
                        if event["type"] == "ACK" and event["seq"] == self.tx_seq:
                            print(f"[{self.device_id}] <--- Valid ACK received for Seq {self.tx_seq}!")
                            ack_received = True
                            break
                
                if ack_received:
                    break
                
                time.sleep(0.01)  # Small yield window to protect microcontroller/CPU scheduling
            
            # 6. EVALUATE TIMEOUT STATUS: Did we get our matching ACK?
            if ack_received:
                # Step forward: Toggle sequence number tracker (0 -> 1 or 1 -> 0) for the next fresh payload
                self.tx_seq = 1 - self.tx_seq
                return True  # Transaction completed successfully!
            else:
                # TIME OUT EVENT: The loop finished its duration check but ack_received remains False
                print(f"[{self.device_id}] !!! Timeout expired! No matching ACK received for Seq {self.tx_seq}.")
                retries += 1
        
        print(f"[{self.device_id}] Fatal: Reached maximum retries ({max_retries}). Channel link is broken.")
        return False



#TEST ENVIRONMENT RUNNER

def simulate_monsoon_channel(clean_bytes: bytes) -> bytes:
    """Deliberately compromises the data stream according to assignment parameters."""
    if not clean_bytes:
        return b""
    
    dirty_stream = bytearray()
    i = 0
    while i < len(clean_bytes):
        rand = random.random()
        
        if rand < 0.05:  # 5% Chance to inject random garbage noise bytes
            dirty_stream.append(random.randint(0x00, 0xFF))
            continue     # Do not advance step counter, inserting byte directly
        elif rand < 0.10: # 5% Chance to drop a valid byte completely
            i += 1
            continue
        elif rand < 0.15: # 5% Chance to maliciously corrupt a byte inline
            dirty_stream.append(clean_bytes[i] ^ random.randint(0x01, 0xFF))
            i += 1
        else:            # 85% Pass-through rate
            dirty_stream.append(clean_bytes[i])
            i += 1
            
    return bytes(dirty_stream)

if __name__ == "__main__":
    print("--- Initiating Wildlife Reserve Station Comm Protocol Test Bench ---")
    random.seed(42)  # Seeded for reproducible metrics execution
    
    arushi_station = CommunicationProtocol(device_id="Arushi_Station")
    abhik_station  = CommunicationProtocol(device_id="Abhik_Station")

    # Sample sensor telemetry metrics payload
    telemetry_payload = b"TEMP=24C;BATT=89%"
    print(f"\nOriginal Payload Size: {len(telemetry_payload)} bytes")

    # 1. Serialization
    serialized = arushi_station.serialize_packet(
        packet_type=CommunicationProtocol.TYPE_DATA, 
        seq_num=arushi_station.tx_seq, 
        payload=telemetry_payload
    )
    print(f"Serialized Framed Packet Output: {serialized.hex().upper()}")

    # 2. Introduce Environment Degradation (Corruptions, Splitting, Merging)
    corrupted_channel_stream = simulate_monsoon_channel(serialized)
    print(f"Stream after channel interference: {corrupted_channel_stream.hex().upper()}")

    # Simulate fragmentation: Packet arrives chopped into two separate arbitrary chunks
    chunk_1 = corrupted_channel_stream[:len(corrupted_channel_stream)//2]
    chunk_2 = corrupted_channel_stream[len(corrupted_channel_stream)//2:]
    print(f"Chunk 1 Transferred: {chunk_1.hex().upper()}")
    print(f"Chunk 2 Transferred: {chunk_2.hex().upper()}")

    # 3. Feed arbitrary chunks sequentially into Abhik's state machine parser
    print("\n--- Running Inbound Parsing FSM Engine ---")
    results = abhik_station.process_incoming_byte_stream(chunk_1)
    results += abhik_station.process_incoming_byte_stream(chunk_2)

    # 4. Analyze Results
    success = False
    for res in results:
        if res["type"] == "DATA":
            print(f"\n[SUCCESS] Decoded Valid Packet!")
            print(f"Sequence Tag: {res['seq']}")
            print(f"Recovered Payload: {res['payload'].decode('utf-8', errors='ignore')}")
            success = True
            
    if not success:
        print("\n[TIMEOUT/DROP] Packet suffered fatal errors under channel noise simulation.")
        print("Protocol engine will now initiate Automatic Retransmission Loop (ARQ).")