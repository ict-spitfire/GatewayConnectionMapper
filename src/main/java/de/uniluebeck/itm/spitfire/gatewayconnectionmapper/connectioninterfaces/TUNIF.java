/**
 * Copyright (c) 2012, all partners of project SPITFIRE (http://www.spitfire-project.eu)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 *  - Neither the name of the University of Luebeck nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package de.uniluebeck.itm.spitfire.gatewayconnectionmapper.connectioninterfaces;

import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.ConnectionMapper;
import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol.IPv6;

/**
 * This class represents a TUN interface which has the capability to read
 * and write data.
 * If you intend to send data to "localhost" or "::1" you should send it
 * to a address which is bound to the TUN interface instead.
 * All written data (if valid) will be routed by the operating system.
 *
 * @author Stefan Hueske
 */
public class TUNIF implements IFReadWriter {

    //system name of the TUN interface
    String interfaceName;
    //instance of connection mapper is only needed to call native methods
    ConnectionMapper connectionMapper = new ConnectionMapper();
    //file descriptor for TUN interface
    int fileDescriptor;

    /**
     * Create a new TUN interface.
     * @param tunIF system name of the TUN interface
     */
    public TUNIF(String tunIF) {
        this.interfaceName = tunIF;
        //allocate TUN interface
        fileDescriptor = connectionMapper.tun_alloc(tunIF);
    }

    /**
     * Read data. Data will contain a IP packet.
     * @param buffer buffer in which the read data will be stored
     * @param nbytes buffer size
     * @return bytes read
     */
    @Override
    public int read(byte[] buffer, int nbytes) {
        return connectionMapper.tun_read(fileDescriptor, buffer, nbytes);
    }

    /**
     * Returns the system name of the TUN interface.
     * @return systems TUN interface name
     */
    @Override
    public String getName() {
        return interfaceName;
    }

    /**
     * Writes nbytes from buffer. The data should be a IP packet.
     * @param buffer byte buffer with data (IP packet)
     * @param nbytes number of bytes which should be written from buffer
     * @return bytes actually written
     */
    @Override
    public int write(byte[] buffer, int nbytes) {
        return connectionMapper.tun_write(fileDescriptor, buffer, nbytes);
    }

    /**
     * Writes a IPv6 packet.
     * @param packet IPv6 packet
     * @return Number of bytes written
     * @throws Exception Will be thrown when encoding of the IPv6 packet fails.
     */
    public int write(IPv6 packet) throws Exception {
        byte[] encodedPacket = packet.encode();
        return connectionMapper.tun_write(fileDescriptor, encodedPacket,
                encodedPacket.length);
    }
}
