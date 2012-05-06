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
package de.uniluebeck.itm.spitfire.gatewayconnectionmapper;

import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.connectioninterfaces.IFReadWriter;
import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.connectioninterfaces.IFReader;
import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol.EthernetFrame;
import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol.IPv6;
import java.io.IOException;
import java.net.InetAddress;
import java.util.LinkedList;
import java.util.List;
import junit.framework.TestCase;

import static de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol.Tools.*;

/**
 * JUnit tests for the mapping functionality.
 * @author Stefan Hueske
 */
public class ConnectionMapperTest extends TestCase {

    byte[] tcpPacket = getByteArrayFromString("0800270026c3080027c6ec3a86dd6000"
            + "000000280640fc000000000000000000000000000022fc000000000000000000"
            + "000000000011d99800506ea3d3ef00000000a002168024a70000020405a00402"
            + "080a001ef81f0000000001030306");
    byte[] udpPacket = getByteArrayFromString("0800270026c3080027c6ec3a86dd6000"
            + "000000261140fc000000000000000000000000000022fc000000000000000000"
            + "00000000001163f416330026c5264401f26458666330303a3a31312216332474"
            + "65737428298cb1f76b6bdf62");
    
    private byte[] modEthPacket(byte[] src, String srcIP, int srcPort,
            String destIP, int destPort) throws Exception {
        EthernetFrame f = new EthernetFrame(src);
        //IPv6Packet p = new IPv6Packet(f.getPayload());
        IPv6 p = new IPv6(f.getPayload());
        p.setSourceIP(InetAddress.getByName(srcIP));
        p.setSourcePort(srcPort);
        p.setDestIP(InetAddress.getByName(destIP));
        p.setDestPort(destPort);
        f.setPayload(p.encode());
        return f.encode();
    }

    private byte[] getIPpacket(byte[] ethernet) throws Exception {
        EthernetFrame f = new EthernetFrame(ethernet);
        return f.getPayload();
    }

    /**
     * Test of mapUDPNetIF method, of class ConnectionMapper.
     */
    public void testMapUDPNetIF() throws Exception {
        //setup values
        ConnectionMapper.tunBoundIP = "fc00::31";
        ConnectionMapper.localUdpServerPort = 33333;
        ConnectionMapper.localTcpServerPort = 8080;
        ConnectionMapper.tunVirtualUdpIP = "fc00::33";
        ConnectionMapper.tunVirtualTcpIP = "fc00::32";

        //Simulate udp request

        //eth1 receive
        VirtualPcapIF pcap = new VirtualPcapIF();
        VirtualTunIF tun = new VirtualTunIF();
        byte[] p1eth = modEthPacket(udpPacket, "fc00::11", 4444, "fc00::22", ConnectionMapper.virtualUDPServerPort);
        System.out.println("SimulateReceivingPcap2: "
                + new IPv6(new EthernetFrame(p1eth).getPayload()));
        pcap.addData(p1eth);
        byte[] buffer = new byte[1900];
        byte[] blockedSourceMac = getHWaddrAsBytes("01:23:45:67:89:00");

        ConnectionMapper.mapUDPNetIF(pcap, buffer, tun, blockedSourceMac);
        
        //check tun written
        Thread.sleep(20); //wait for data in case of multithreading
        IPv6 p = new IPv6(tun.readLastSend());
        System.out.println("VirtualTUNwritten: " + p);
        assertEquals(p.getSourceIP(), InetAddress.getByName(ConnectionMapper.tunVirtualUdpIP));
        int mappedPort = p.getSourcePort();
        assertEquals(p.getDestIP(), InetAddress.getByName(ConnectionMapper.tunBoundIP));
        assertEquals(p.getDestPort(), ConnectionMapper.localUdpServerPort);
        
        //simulate tcp request on tun
        p = new IPv6(getIPpacket(tcpPacket));
        p.setSourceIP(InetAddress.getByName(ConnectionMapper.tunBoundIP));
        int localTcpPort = 22222;
        p.setSourcePort(localTcpPort);
        p.setDestIP(InetAddress.getByName(ConnectionMapper.tunVirtualTcpIP));
        p.setDestPort(mappedPort);
        System.out.println("SimulateReceivingTUN: " + p);
        tun.addReceivedData(p.encode());

        ConnectionMapper.mapTUNNetIF(tun, buffer);

        //check tun written
        Thread.sleep(20); //wait for data in case of multithreading
        p = new IPv6(tun.readLastSend());
        System.out.println("VirtualTUNwritten: " + p);
        assertEquals(p.getSourceIP(), InetAddress.getByName("fc00::11"));
        assertEquals(p.getSourcePort(), localTcpPort);
        assertEquals(p.getDestIP(), InetAddress.getByName("fc00::22"));
        assertEquals(p.getDestPort(), ConnectionMapper.virtualTCPServerPort);

         //simulate eth0 receive tcp answer
        p1eth = modEthPacket(tcpPacket, "fc00::22", ConnectionMapper.virtualTCPServerPort, "fc00::11", localTcpPort);
        System.out.println("SimulateReceivingPcap1: "
                + new IPv6(new EthernetFrame(p1eth).getPayload()));
        pcap.addData(p1eth);

        ConnectionMapper.mapTCPNetIF(pcap, buffer, tun, blockedSourceMac);

        //check tun written
        Thread.sleep(20); //wait for data in case of multithreading
        p = new IPv6(tun.readLastSend());
        System.out.println("VirtualTUNwritten: " + p);
        assertEquals(p.getSourceIP(), InetAddress.getByName(ConnectionMapper.tunVirtualTcpIP));
        assertEquals(p.getSourcePort(), mappedPort);
        assertEquals(p.getDestIP(), InetAddress.getByName(ConnectionMapper.tunBoundIP));
        assertEquals(p.getDestPort(), localTcpPort);

        //simulate udp answer on tun
        p = new IPv6(getIPpacket(udpPacket));
        p.setSourceIP(InetAddress.getByName(ConnectionMapper.tunBoundIP));
        p.setSourcePort(ConnectionMapper.localUdpServerPort);
        p.setDestIP(InetAddress.getByName(ConnectionMapper.tunVirtualUdpIP));
        p.setDestPort(mappedPort);
        System.out.println("SimulateReceivingTUN: " + p);
        tun.addReceivedData(p.encode());

        ConnectionMapper.mapTUNNetIF(tun, buffer);

        //check tun written
        Thread.sleep(20); //wait for data in case of multithreading
        p = new IPv6(tun.readLastSend());
        System.out.println("VirtualTUNwritten: " + p);
        assertEquals(p.getSourceIP(), InetAddress.getByName("fc00::22"));
        assertEquals(p.getSourcePort(), ConnectionMapper.virtualUDPServerPort);
        assertEquals(p.getDestIP(), InetAddress.getByName("fc00::11"));
        assertEquals(p.getDestPort(), 4444);
        
    }
    
    /**
     * Test of mapping, of class ConnectionMapper.
     */
    public void testMapTCPNetIF() throws Exception {
        //setup values
        ConnectionMapper.tunBoundIP = "fc00::31";
        ConnectionMapper.localUdpServerPort = 33333;
        ConnectionMapper.localTcpServerPort = 8080;
        ConnectionMapper.tunVirtualUdpIP = "fc00::33";
        ConnectionMapper.tunVirtualTcpIP = "fc00::32";

        //Simulate tcp request

        //eth0 receive
        VirtualPcapIF pcap = new VirtualPcapIF();
        VirtualTunIF tun = new VirtualTunIF();
        byte[] p1eth = modEthPacket(tcpPacket, "fc00::22", 30000, "fc00::11", ConnectionMapper.virtualTCPServerPort);
        System.out.println("SimulateReceivingPcap1: "
                + new IPv6(new EthernetFrame(p1eth).getPayload()));
        pcap.addData(p1eth);
        byte[] buffer = new byte[1900];
        byte[] blockedSourceMac = getHWaddrAsBytes("01:23:45:67:89:00");

        ConnectionMapper.mapTCPNetIF(pcap, buffer, tun, blockedSourceMac);

        //check tun written
        Thread.sleep(20); //wait for data in case of multithreading
        IPv6 p = new IPv6(tun.readLastSend());
        System.out.println("VirtualTUNwritten: " + p);
        assertEquals(p.getSourceIP(), InetAddress.getByName(ConnectionMapper.tunVirtualTcpIP));
        int mappedPort = p.getSourcePort();
        assertEquals(p.getDestIP(), InetAddress.getByName(ConnectionMapper.tunBoundIP));
        assertEquals(p.getDestPort(), ConnectionMapper.localTcpServerPort);

        //simulate udp request on tun
        p = new IPv6(getIPpacket(udpPacket));
        p.setSourceIP(InetAddress.getByName(ConnectionMapper.tunBoundIP));
        int localUdpPort = 43210;
        p.setSourcePort(localUdpPort);
        p.setDestIP(InetAddress.getByName(ConnectionMapper.tunVirtualUdpIP));
        p.setDestPort(mappedPort);
        System.out.println("SimulateReceivingTUN: " + p);
        tun.addReceivedData(p.encode());

        ConnectionMapper.mapTUNNetIF(tun, buffer);

        //check tun written
        Thread.sleep(20); //wait for data in case of multithreading
        p = new IPv6(tun.readLastSend());
        System.out.println("VirtualTUNwritten: " + p);
        assertEquals(p.getSourceIP(), InetAddress.getByName("fc00::22"));
        assertEquals(p.getSourcePort(), 30000);
        assertEquals(p.getDestIP(), InetAddress.getByName("fc00::11"));
        assertEquals(p.getDestPort(), ConnectionMapper.virtualUDPServerPort);

        //simulate eth1 receive udp answer
        p1eth = modEthPacket(udpPacket, "fc00::11", ConnectionMapper.virtualUDPServerPort, "fc00::22", 30000);
        System.out.println("SimulateReceivingPcap2: "
                + new IPv6(new EthernetFrame(p1eth).getPayload()));
        pcap.addData(p1eth);

        ConnectionMapper.mapUDPNetIF(pcap, buffer, tun, blockedSourceMac);

        //check tun written
        Thread.sleep(20); //wait for data in case of multithreading
        p = new IPv6(tun.readLastSend());
        System.out.println("VirtualTUNwritten: " + p);
        assertEquals(p.getSourceIP(), InetAddress.getByName(ConnectionMapper.tunVirtualUdpIP));
        assertEquals(p.getSourcePort(), mappedPort);
        assertEquals(p.getDestIP(), InetAddress.getByName(ConnectionMapper.tunBoundIP));
        assertEquals(p.getDestPort(), localUdpPort);

        //simulate tcp answer on tun
        p = new IPv6(getIPpacket(tcpPacket));
        p.setSourceIP(InetAddress.getByName(ConnectionMapper.tunBoundIP));
        p.setSourcePort(ConnectionMapper.localTcpServerPort);
        p.setDestIP(InetAddress.getByName(ConnectionMapper.tunVirtualTcpIP));
        p.setDestPort(mappedPort);
        System.out.println("SimulateReceivingTUN: " + p);
        tun.addReceivedData(p.encode());

        ConnectionMapper.mapTUNNetIF(tun, buffer);

        //check tun written
        Thread.sleep(20); //wait for data in case of multithreading
        p = new IPv6(tun.readLastSend());
        System.out.println("VirtualTUNwritten: " + p);
        assertEquals(p.getSourceIP(), InetAddress.getByName("fc00::11"));
        assertEquals(p.getSourcePort(), ConnectionMapper.virtualTCPServerPort);
        assertEquals(p.getDestIP(), InetAddress.getByName("fc00::22"));
        assertEquals(p.getDestPort(), 30000);
    }

    private static class VirtualPcapIF implements IFReader {
        String name;
        List<byte[]> data = new LinkedList<byte[]>();

        public VirtualPcapIF() throws IOException {
            name = "VirtualPcap";
        }

        synchronized void addData(byte[] ethernet) {
            data.add(ethernet);
        }

        @Override
        synchronized public int read(byte[] buffer, int nbytes) {
            if (data.isEmpty()) {
                return 0;
            }
            byte[] d = data.get(0);
            int res = 0;
            for (int i = 0; i < nbytes && i < d.length; i++) {
                buffer[i] = d[i];
                res++;
            }
            data.remove(0);
            return res;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    private static class VirtualTunIF implements IFReadWriter {

        String name;

        List<byte[]> received = new LinkedList<byte[]>();
        List<byte[]> written = new LinkedList<byte[]>();

        public VirtualTunIF() {
            name = "VirtualTUN";
        }

        synchronized void addReceivedData(byte[] ipPacket) {
            received.add(ipPacket);
        }

        @Override
        public synchronized int read(byte[] buffer, int nbytes) {
            if (received.isEmpty()) {
                return 0;
            }
            byte[] d = received.get(0);
            int res = 0;
            for (int i = 0; i < nbytes && i < d.length; i++) {
                buffer[i] = d[i];
                res++;
            }
            received.remove(0);
            return res;
        }

        @Override
        public synchronized int write(byte[] buffer, int nbytes) {
            try {
                written.add(getBytes(buffer, 0, nbytes));
                return nbytes;
            } catch (Exception ex) {
                return 0;
            }
        }

        synchronized byte[] readLastSend() {
            if (written.isEmpty()) {
                return null;
            }
            byte[] r = written.get(0);
            written.remove(0);
            return r;
        }

        @Override
        public String getName() {
            return name;
        }

    }
}
