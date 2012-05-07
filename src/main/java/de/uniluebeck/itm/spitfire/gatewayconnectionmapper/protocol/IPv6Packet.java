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
package de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol;

import java.net.InetAddress;
import static de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol.Tools.*;

/**
* This class represents a IPv6Packet packet and if it carries UDP or TCP payload also
* the destination and source port.
* All important IPv6Packet fields for this use case can be modified and re-encoded again.
* There are also source and destination port fields,
* which can only be used if the payload of this packet contains
* a UDP or TCP header.
* Also checksum recalculation will happen automatically
* for UDP and TCP payload.
*
* @author Stefan Hueske
*/
public class IPv6Packet {

    InetAddress sourceIP;
    InetAddress destIP;
    private byte[] payload;
    int nextHeader;

    //Port fields are only valid for UDP and TCP payload, otherwise -1
    int sourcePort;
    int destPort;

    //This array contains the original header with
    //all fields which can not be manipulated by this class.
    //These fields will be adopted when encoding the packet again.
    private byte[] originalHeader;

    /**
     * Create a new instance by decoding a passed IPv6Packet byte array.
     * @param data IPv6Packet byte array
     * @throws Exception Will be thrown when decoding fails
     */
    public IPv6Packet(byte[] data) throws Exception {
        sourceIP = InetAddress.getByAddress(getBytes(data, 22 - 14, 16));
        destIP = InetAddress.getByAddress(getBytes(data, 38 - 14, 16));
        payload = getBytes(data, 54 - 14, getUnsignedInt(getBytes(data, 18 - 14, 2)));
        nextHeader = getUnsignedInt(getBytes(data, 20 - 14, 1));
        originalHeader = getBytes(data, 0, 40);

        if (isTCP() || isUDP()) {
            sourcePort = getUnsignedInt(getBytes(data, 54 - 14, 2));
            destPort = getUnsignedInt(getBytes(data, 56 - 14, 2));
        } else {
            sourcePort = -1;
            destPort = -1;
        }
    }

    /**
     * Create a new instance by decoding a passed IPv6Packet byte array.
     * @param buffer IPv6Packet byte array
     * @param nBytes Reads only the first n bytes from buffer
     * @throws Exception Will be thrown when decoding fails
     */
    public IPv6Packet(byte[] buffer, int nBytes) throws Exception {
        this(getBytes(buffer, 0, nBytes));
    }

    /**
     * Encode this IPv6Packet packet.
     * @return Encoded byte array
     * @throws Exception Will be thrown when encoding fails
     */
    public byte[] encode() throws Exception {
        byte[] res = new byte[40 + payload.length];
        insertBytes(res, originalHeader, 0, 40);
        insertBytes(res, sourceIP.getAddress(), 22 - 14, 16);
        insertBytes(res, destIP.getAddress(), 38 - 14, 16);
        insertBytes(res, payload, 40, payload.length);
        if(isTCP() || isUDP()) {
            insertBytes(res, getBytesFromInt(sourcePort), 40, 2);
            insertBytes(res, getBytesFromInt(destPort), 42, 2);
        }
        //payload length
        insertBytes(res, getBytesFromInt(payload.length), 18 - 14, 2);
        if (isTCP()) {
            //insert checksum
            insertBytes(res, calculateTCPchecksum(this), 70 - 14, 2);
        }
        if (isUDP()) {
            //insert checksum
            insertBytes(res, calculateUDPchecksum(this), 60 - 14, 2);
        }

        return res;
    }

    /**
     * Returns the destination IPv6Packet address.
     * @return Destination address as InetAddress
     */
    public InetAddress getDestIP() {
        return destIP;
    }

    /**
     * Sets a new destination address.
     * @param destIP IPv6Packet destination address
     */
    public void setDestIP(InetAddress destIP) {
        this.destIP = destIP;
    }

    /**
     * Returns the destination port if this packet contains UDP or TCP payload,
     * -1 else.
     * @return Destination port if valid, -1 else
     */
    public int getDestPort() {
        return destPort;
    }

    /**
     * Sets a new destination port.
     * This field will be ignored if payload does not contain UDP or TCP payload.
     * @param destPort New destination port
     */
    public void setDestPort(int destPort) {
        this.destPort = destPort;
    }

    /**
     * Returns the source IPv6Packet address.
     * @return Source address
     */
    public InetAddress getSourceIP() {
        return sourceIP;
    }

    /**
     * Sets a new source address.
     * @param sourceIP New source IPv6Packet address
     */
    public void setSourceIP(InetAddress sourceIP) {
        this.sourceIP = sourceIP;
    }

   /**
     * Returns the source port if this packet contains UDP or TCP payload,
     * -1 else.
     * @return Source port if valid, -1 else
     */
    public int getSourcePort() {
        return sourcePort;
    }

    /**
     * Sets a new source port.
     * This field will be ignored if payload does not contain UDP or TCP payload.
     * @param sourcePort New source port
     */
    public void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }

    @Override
    public String toString() {
        return "IPv6Packet: " + "[" + sourceIP + "]:" + sourcePort + " -> "
                + "[" + destIP + "]:" + destPort;
    }

    /**
     * Returns true if the next header field is 6.
     * @return True if payload contains TCP data.
     */
    public boolean isTCP() {
        return nextHeader == 6;
    }

    /**
     * Returns true if the next header field is 17.
     * @return True if payload contains UDP data.
     */
    public boolean isUDP() {
        return nextHeader == 17;
    }

    /**
     * Returns the payload of this IPv6Packet packet.
     * @return Payload as byte array
     */
    public byte[] getPayload() {
        return payload;
    }

    /**
     * Sets a new payload.
     * @param payload New payload as byte array
     */
    public void setPayload(byte[] payload) {
        this.payload = payload;
    }

    /**
     * Returns the next header field.
     * @return Next header as int
     */
    public int getNextHeader() {
        return nextHeader;
    }

    /**
     * Sets a new next header field.
     * @param nextHeader New next header as int
     */
    public void setNextHeader(int nextHeader) {
        this.nextHeader = nextHeader;
    }

    /**
     * Calculates a new TCP checksum.
     * @param p IPv6Packet packet with TCP payload
     * @return Checksum field as byte array
     * @throws Exception Will be thrown when calculation fails
     */
    private static byte[] calculateTCPchecksum(IPv6Packet p) throws Exception {
        if (!p.isTCP()) {
            throw new Exception("IPv6Packet Packet must contain TCP payload for this operation! " + p);
        }
        int padding = 0;
        if (p.getPayload().length % 2 != 0) {
            padding = 1;
        }
        byte[] pseudoheader = new byte[40 + p.getPayload().length + padding];
        byte[] tcpData = p.getPayload();
        insertBytes(pseudoheader, tcpData, 40, tcpData.length);
        insertBytes(pseudoheader, p.getSourceIP().getAddress(), 0, 16);
        insertBytes(pseudoheader, p.getDestIP().getAddress(), 16, 16);
        insertBytes(pseudoheader, getBytesFromInt(tcpData.length), 32, 4);
        insertBytes(pseudoheader, getBytesFromInt(p.getNextHeader()), 39, 1);
        insertBytes(pseudoheader, getBytesFromInt(p.getSourcePort()), 40, 2);
        insertBytes(pseudoheader, getBytesFromInt(p.getDestPort()), 42, 2);

        byte[] checksum = new byte[2];
        insertBytes(pseudoheader, checksum, 56, 2);
        int res = 0;
        for (int i = 0; i < pseudoheader.length; i += 2) {
            int val = getUnsignedInt(getBytes(pseudoheader, i, 2));
            res = add16bitOnesComplement(res, val);
        }
        res = (~res) & 0x0000FFFF;
        checksum = getBytesFromInt(res);

        if (checksum.length == 1) {
            byte[] r = new byte[2];
            insertBytes(r, checksum, 1, 1);
        }
        return checksum;
    }

    /*public static void main(String[] args) throws Exception {
        String originalPacket = "0004fffe0000000000000000000086dd6000000000261140fc000000000000000000000000000031fc0000000000000000000000000000338235000100263251450199c0110048666330303a3a33332101247465737427a16e9b27b072e3";
        byte[] o = getByteArrayFromString(originalPacket);
        byte[] orgIP = getBytes(o, 16, o.length - 16);
        IPv6Packet p = new IPv6Packet(orgIP);
        System.out.println("Checksum: " + "32 51");
        System.out.println("Checksum: " + getBytesAsString(calculateUDPchecksum(p)));

//        String expectedPacket = "0000fffe0000000000000000000086dd6000000000280640fc000000000000000000000000000032fc00000000000000000000000000002100011f902aba49bc00000000a002168049bc0000020405a00402080a010b0fd10000000001030306";
//        byte[] e = getByteArrayFromStringDebug(expectedPacket);
//        byte[] expected = getBytes(e, 16, e.length - 16);
//
//        p.setSourceIP(InetAddress.getByName("fc00::32"));
//        p.setSourcePort(1);
//        p.setDestIP(InetAddress.getByName("fc00::21"));
//        p.setDestPort(8080); //localhost-server HTTP port
//
        System.out.println(compareBytes(orgIP, p.encode()));

//        IPv6Packet p2 = new IPv6Packet(p.encode());
//
//        System.out.println(compareBytes(p2.encode(), p.encode()));
//        System.out.println(compareBytes(p2.encode(), new IPv6Packet(p2.encode()).encode()));
    }*/

    /**
     * Calculates a new UDP checksum.
     * @param p IPv6Packet packet with UDP payload
     * @return Checksum field as byte array
     * @throws Exception Will be thrown when calculation fails
     */
    private static byte[] calculateUDPchecksum(IPv6Packet p) throws Exception {
        if (!p.isUDP()) {
            throw new Exception("IPv6Packet Packet must contain UDP payload for this operation! " + p);
        }
        int padding = 0;
        if (p.getPayload().length % 2 != 0) {
            padding = 1;
        }
        byte[] pseudoheader = new byte[40 + p.getPayload().length + padding];
        byte[] udpData = p.getPayload();
        insertBytes(pseudoheader, udpData, 40, udpData.length);
        insertBytes(pseudoheader, p.getSourceIP().getAddress(), 0, 16);
        insertBytes(pseudoheader, p.getDestIP().getAddress(), 16, 16);
        insertBytes(pseudoheader, getBytesFromInt(p.getSourcePort()), 40, 2);
        insertBytes(pseudoheader, getBytesFromInt(p.getDestPort()), 42, 2);
        insertBytes(pseudoheader, getBytesFromInt(udpData.length), 32, 4);
        insertBytes(pseudoheader, getBytesFromInt(p.getNextHeader()), 39, 1);
        byte[] checksum = new byte[2];
        insertBytes(pseudoheader, checksum, 46, 2);
        int res = 0;
        for (int i = 0; i < pseudoheader.length; i += 2) {
            int val = getUnsignedInt(getBytes(pseudoheader, i, 2));
            res = add16bitOnesComplement(res, val);
        }
        res = (~res) & 0x0000FFFF;

        if (res == 0) {
            byte[] r = {(byte) 0xFF, (byte) 0xFF};
            return r;
        }

        checksum = getBytesFromInt(res);

        if (checksum.length == 1) {
            byte[] r = new byte[2];
            insertBytes(r, checksum, 1, 1);
        }
        return checksum;
    }

//    /**
//     * Returns a copy of this IPv6Packet packet with reversed
//     * IP/Port Destination <-> Source data.
//     * @return Copy of this packet with reversed connection data.
//     */
//    public IPv6Packet reverseConnection() {
//        try {
//            //TODO dirty, use clone() instead
//            IPv6Packet res = new IPv6Packet(encode());
//            res.setSourceIP(destIP);
//            res.setSourcePort(destPort);
//            res.setDestIP(sourceIP);
//            res.setDestPort(sourcePort);
//            return res;
//        } catch (Exception ex) {
//        }
//        return null;
//    }

}
