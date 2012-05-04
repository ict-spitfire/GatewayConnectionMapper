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
import java.io.IOException;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;

/**
 * This class represents a Pcap interface which has the capability to read data
 * from a systems ethernet interface.
 * The read data will contain a ethernet frame.
 *
 * @author Stefan Hueske
 */
public class PcapIF implements IFReader {

    String name;
    Pcap pcap;

    /**
     * Create a new Pcap interface.
     * @param ifName ethernet interfaces system name (eg. "eth0")
     * @throws IOException Will be thrown when opening failed
     */
    public PcapIF(String ifName) throws IOException {
        this.name = ifName;
        StringBuilder errbuf = new StringBuilder(); // for error messages
        int snaplen = 64 * 1024;           // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 0;
        pcap = Pcap.openLive(ifName, snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            ConnectionMapper.log.error("Error while opening device for capture: "
                    + errbuf.toString());
        }
    }

    /**
     * Read data. Data will contain a ethernet frame.
     * @param buffer buffer in which the read data will be stored
     * @param nbytes buffer size
     * @return bytes read
     */
    @Override
    public int read(byte[] buffer, int nbytes) {
        JBuffer buf = new JBuffer(buffer);
        PcapHeader header = new PcapHeader();
        pcap.nextEx(header, buf);
        for (int i = 0; i < buf.size(); i++) {
            buffer[i] = buf.getByte(i);
        }
        return buf.size();
    }

    /**
     * Returns the name of the ethernet interface on which Pcap listens to.
     * @return ethernet interface name
     */
    @Override
    public String getName() {
        return name;
    }
}