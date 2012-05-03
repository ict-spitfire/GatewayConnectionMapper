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

import java.io.IOException;
import java.util.LinkedList;
import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.connectioninterfaces.IFReadWriter;
import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.connectioninterfaces.IFReader;
import java.util.ArrayList;
import static de.uniluebeck.itm.spitfire.gatewayconnectionmapper.ConnectionTable.*;
import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.connectioninterfaces.PcapIF;
import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.connectioninterfaces.TUNIF;
import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol.EthernetFrame;
import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol.IPv6;
import java.net.InetAddress;
import java.util.List;

import org.apache.log4j.*;

import static de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol.Tools.*;


/**
 * After calling ConnectionMapper.start() all incoming packets which match
 * the specified criteria will be forwarded to localhost with a unique virtual
 * source address and port. The gateway-logic (which is not part of this project) 
 * should contain a local
 * TCP server on localTcpServerPort and a
 * UDP server on localUdpServerPort.
 * If you are running these servers within the same JVM, you can access the
 * original connection data of each connection/packet with help of class
 * ConnectionTable.
 *
 * @author Stefan Hueske
 */
public class ConnectionMapper {
    //Logger
    public static Logger logger = Logger.getLogger(ConnectionMapper.class.getName());

    //Has to be the same IP owned by the tun interface
    public static String tunBoundIP;

    //UDP server port
    static int localUdpServerPort;

    //TCP server port
    static int localTcpServerPort;

    //Virtual Server Ports
    public static int virtualTCPServerPort = 80;
    public static int virtualUDPServerPort = 5683;
    
    //From an external point of view the conversion will be transparent,
    //from an internal point of view all communication takes place between
    //localhost and the TUN interface. In order to achieve this,
    //virtual IP addresses will be used to ensure responding packets will
    //be captured and associated the right way.
    //For further information
    //please refer to CoAPHTTPGateway - Sequenzdiagramm.pdf
    //TCP packets: localhost(tunBoundIP) <--> tunVirtualTcpIP
    //UDP packets: localhost(tunBoundIP) <--> tunVirtualUdpIP
    static String tunVirtualUdpIP;
    public static String tunVirtualTcpIP;
    
    //List containing all local bound IP addresses
    //these will be ignored while processing incoming traffic
    private static List<InetAddress> localBoundIPs = new ArrayList<InetAddress>();
    
    /**
     * Allocate/open the TUN interface.
     * @param dev TUN interface name
     * @return file descriptor
     */
    public native int tun_alloc(String dev);
    
    /**
     * Read bytes from a TUN interface
     * @param fd file descriptor
     * @param buffer the read data will be written in this buffer
     * @param nbytes max buffer size / bytes to read
     * @return bytes read
     */
    public native int tun_read(int fd, byte[] buffer, int nbytes);

    /**
     * Write bytes to a TUN interface
     * @param fd file descriptor
     * @param buffer data to write
     * @param nbytes bytes to write
     * @return bytes written
     */
    public native int tun_write(int fd, byte[] buffer, int nbytes);
    
    /**
     * Starts the GatewayConnectionMapper.
     * The application which calls this function must have the right to
     * access TUN Interfaces. User with CAP_NET_ADMIN capability or
     * root under linux.
     * 
     * @param tunWrapperPath path to the TUN wrapper C library
     * @param log4jLogger log4j Logger
     * @param tunBoundIP IP which is bound to the TUN interface
     * @param localUdpServerPort port on which the UDP server listens
     * @param localHttpServerPort port on which the TCP server listens
     * @param tunUdpIP UDP specific ip address in the tunBoundIP network
     * @param tunTcpIP TCP specific ip address in the tunBoundIP network
     * @param udpNetIf ethernet interface to the UDP network
     * @param udpNetIfMac mac address of udpNetIf
     * @param tcpNetIf ethernet interface to the TCP network
     * @param tcpNetIfMac mac address of tcpNetIf
     * @param tunNetIf tun interface name
     * @throws Exception will be thrown when starting fails
     */
    public static void start(String tunWrapperPath, Logger log4jLogger,
            String tunBoundIP, int localUdpServerPort, int localHttpServerPort,
            String tunUdpIP, String tunTcpIP,
            String udpNetIf, String udpNetIfMac,
            String tcpNetIf, String tcpNetIfMac,
            String tunNetIf) throws Exception {

        //load TUN wrapper
        System.load(tunWrapperPath);
        
        //logger = log4jLogger;
        ConnectionMapper.tunBoundIP = tunBoundIP;
        ConnectionMapper.localUdpServerPort = localUdpServerPort;
        ConnectionMapper.localTcpServerPort = localHttpServerPort;
        ConnectionMapper.tunVirtualUdpIP = tunUdpIP;
        ConnectionMapper.tunVirtualTcpIP = tunTcpIP;


        //create Pcap and TUN interfaces
        PcapIF tcpPcap = new PcapIF(tcpNetIf);
        byte[] tcpPcapmac = getHWaddrAsBytes(tcpNetIfMac);
        PcapIF udpPcap = new PcapIF(udpNetIf);
        byte[] udpPcapmac = getHWaddrAsBytes(udpNetIfMac);
        TUNIF tun = new TUNIF(tunNetIf);
        
        //create threads
        TcpNetIfPcapThread tcpThread =
                new TcpNetIfPcapThread(tun, tcpPcap, tcpPcapmac);
        UdpNetIfPcapThread udpThread =
                new UdpNetIfPcapThread(tun, udpPcap, udpPcapmac);
        TunNetIfThread tunThread = new TunNetIfThread(tun);
        
        //start threads
        tcpThread.start();
        udpThread.start();
        tunThread.start();

        logger.info("GatewayConnectionMapper started.");
        
        //TODO create function to stop connection mapper
        //TODO prevent starting when ConnectionMapper already runs
    }

    /**
     * Starts the GatewayConnectionMapper.
     * The application which calls this function must have the right to
     * access TUN Interfaces. User with CAP_NET_ADMIN capability or
     * root under linux.
     * 
     * @param tunWrapperPath path to the TUN wrapper C library
     * @param log4jLogger log4j Logger
     * @param tunBoundIP IP which is bound to the TUN interface
     * @param localUdpServerPort port on which the UDP server listens
     * @param localHttpServerPort port on which the TCP server listens
     * @param tunUdpIP UDP specific ip address in the tunBoundIP network
     * @param tunTcpIP TCP specific ip address in the tunBoundIP network
     * @param udpNetIf ethernet interface to the UDP network
     * @param udpNetIfMac mac address of udpNetIf
     * @param tcpNetIf ethernet interface to the TCP network
     * @param tcpNetIfMac mac address of tcpNetIf
     * @param tunNetIf tun interface name
     * @param localBoundIPs
     * @throws Exception will be thrown when starting fails
     */
    public static void start(String tunWrapperPath, Logger log4jLogger, 
            String tunBoundIP, int localUdpServerPort, int localHttpServerPort,
            String tunUdpIP, String tunTcpIP,
            String udpNetIf, String udpNetIfMac,
            String tcpNetIf, String tcpNetIfMac,
            String tunNetIf, List<InetAddress> localBoundIPs) throws Exception {

        for (InetAddress a : localBoundIPs) {
            ConnectionMapper.localBoundIPs.add(a);
        }

        start(tunWrapperPath, log4jLogger, tunBoundIP, localUdpServerPort, 
                localHttpServerPort, tunUdpIP, tunTcpIP, udpNetIf, udpNetIfMac, 
                tcpNetIf, tcpNetIfMac, tunNetIf);
    }

    /**
     * Test if destination of an IPv6 packet is a local bound ip.
     * @param packet IPv6 packet
     * @return True if destination address is locally bound.
     */
    public static synchronized boolean targetIsBoundIP(IPv6 packet) {
        for (InetAddress a : localBoundIPs) {
            if (a.equals(packet.getDestIP())) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Read a single IPv6 packet and modify its connection data. (UDP side)
     * @param pcap UDP side pcap interface to read data from
     * @param buffer Buffer in which the read data will be stored
     * @param tun TUN interface to write the modified packet
     * @param blockedSourceMac If the IPv6 packet has this source mac, it will
     * be ignored
     * @throws Exception 
     */
    static void mapUDPNetIF(IFReader pcap, byte[] buffer, IFReadWriter tun, byte[] blockedSourceMac) throws Exception {
        int bytesRead = pcap.read(buffer, buffer.length);
        EthernetFrame frame = new EthernetFrame(buffer, bytesRead);
        byte[] framePayload = frame.getPayload();
        if (frame.isIPv6() && !byteArrayEquals(frame.getSourceMac(), blockedSourceMac)) {
            //process incoming traffic only
            IPv6 readPacket = null;
            try {
                readPacket = new IPv6(framePayload);
            } catch (Exception e) {
                logger.debug("UDP IF: Non IPv6 packet received. Will be ignored...");
                //drop packet
                return;
            }

            if (readPacket.getDestIP().isLinkLocalAddress() 
                    || readPacket.getDestIP().isMulticastAddress() 
                    || ConnectionMapper.targetIsBoundIP(readPacket)) {
                //packet will be ignored because
                //its destination is locally bound or not UDP
                return;
            }
            
            if (readPacket.isUDP()) {
                ConnectionTable table = ConnectionTable.getInstance();
                int mappedPort = table.getMappedPortFromUDPResponseForTCPRequest(readPacket);
                if (readPacket.getDestPort() == ConnectionMapper
                    .virtualUDPServerPort || mappedPort != -1) {
                    //The read packet is either a new request with dest. port
                    //virtualUDPServerPort or a packet associated to an existing
                    //connection.
                    int packetSourcePort;
                    Request request;
                    if (mappedPort == -1) {
                        //UDP packet is a UDP request to a TCP server
                        packetSourcePort = table.mapUdpRequest(readPacket);
                        request = table.getUdpRequest(packetSourcePort);
                    } else {
                        //UDP packet it a UDP response to a TCP client
                        packetSourcePort = mappedPort;
                        request = table.getTcpRequest(mappedPort);
                    }

                    ConnectionMapper.logger.debug("UDP IF: Incoming UDP packet mapped to " + request);
                    //modify IPv6 packet
                    readPacket.setSourceIP(InetAddress.getByName(ConnectionMapper.tunVirtualUdpIP));
                    readPacket.setSourcePort(packetSourcePort);
                    readPacket.setDestIP(InetAddress.getByName(ConnectionMapper.tunBoundIP));
                    readPacket.setDestPort(request.getLocalUdpPort());
                }
            }
            //If the packet does not carry UDP payload or it is neither
            //targeted to a virtualUDPServerPort nor associated to an
            //existing connection, it will written to the TUN interface without
            //any modification. Afterwards the operating system will route
            //the packet to its originally destination.
            
            //send packet
            byte[] encodedPacket = readPacket.encode();
            tun.write(encodedPacket, encodedPacket.length);
        }
    }

    /**
     * Read a single IPv6 packet and modify its connection data. (TCP side)
     * @param pcap TCP side pcap interface to read data from
     * @param buffer Buffer in which the read data will be stored
     * @param tun TUN interface to write the modified packet
     * @param blockedSourceMac If the IPv6 packet has this source mac, it will
     * be ignored
     * @throws Exception 
     */
    static void mapTCPNetIF(IFReader pcap, byte[] buffer, IFReadWriter tun, byte[] blockedSourceMac) throws Exception {
        int bytesRead = pcap.read(buffer, buffer.length);
        EthernetFrame frame = new EthernetFrame(buffer, bytesRead);
        byte[] framePayload = frame.getPayload();
        if (frame.isIPv6() && !byteArrayEquals(frame.getSourceMac(), blockedSourceMac)) {
            //process incoming traffic only
            IPv6 readPacket = null;
            try {
                readPacket = new IPv6(framePayload);
            } catch (Exception e) {
                logger.debug("TCP IF: Non IPv6 packet received. Will be ignored...");
                //drop packet
                return;
            }
            
            if (readPacket.getDestIP().isLinkLocalAddress() 
                    || readPacket.getDestIP().isMulticastAddress() 
                    || ConnectionMapper.targetIsBoundIP(readPacket)) {
                //packet will be ignored because
                //its destination is locally bound
                return;
            }
            
            if (readPacket.isTCP()) {
                ConnectionTable table = ConnectionTable.getInstance();
                ConnectionMapper.logger.debug("TCP IF: TCP packet received: " + readPacket);
                int mappedPort = table.getMappedPortFromTCPResponseForUDPRequest(readPacket);
                if (readPacket.getDestPort() == ConnectionMapper
                    .virtualTCPServerPort || mappedPort != -1) {
                    //The read packet is either a new request with dest. port
                    //virtualTCPServerPort or a packet associated to an existing
                    //connection.
                    int packetSourcePort;
                    Request request;
                    if (mappedPort == -1) {
                        //TCP packet is TCP request to a UDP server
                        packetSourcePort = table.mapTcpRequest(readPacket);
                        request = table.getTcpRequest(packetSourcePort);
                    } else {
                        //TCP packet is a TCP response to a UDP client
                        packetSourcePort = mappedPort;
                        request = table.getUdpRequest(mappedPort);
                    }

                    ConnectionMapper.logger.debug("TCP IF: Incoming TCP packet mapped to " + request);
                    //modify IPv6 packet
                    readPacket.setSourceIP(InetAddress.getByName(ConnectionMapper.tunVirtualTcpIP));
                    readPacket.setSourcePort(packetSourcePort);
                    readPacket.setDestIP(InetAddress.getByName(ConnectionMapper.tunBoundIP));
                    readPacket.setDestPort(request.getLocalTcpPort());
                }
            }
            //If the packet does not carry TCP payload or it is neither
            //targeted to a virtualTCPServerPort nor associated to an
            //existing connection, it will written to the TUN interface without
            //any modification. Afterwards the operating system will route
            //the packet to its originally destination.
            
            //send packet
            byte[] encodedPacket = readPacket.encode();
            tun.write(encodedPacket, encodedPacket.length);
        }
    }
    
    /**
     * Read a single IPv6 packet and modify its connection data. (TUN interface)
     * @param tun TUN interface
     * @param buffer Buffer in which the read data will be stored
     * @throws Exception 
     */
    static void mapTUNNetIF(IFReadWriter tun, byte[] buffer) throws Exception {
        int bytesRead = tun.read(buffer, buffer.length);
        IPv6 readPacket = new IPv6(buffer, bytesRead);
        final ConnectionTable table = ConnectionTable.getInstance();
        if (readPacket.getDestIP().equals(InetAddress.getByName(ConnectionMapper.tunVirtualTcpIP))) {
            //readPacket contains TCP data
            Request request = table.getRequest(readPacket.getDestPort());
            if (request == null) {
                //readPacket cannot be associated to a table entry
                //no information available to restore originally connection data
                ConnectionMapper.logger.error("Unmappable packet on tun if: " + readPacket
                + " Maybe caused by gateway restart?");
                return;
            }
            if (readPacket.getSourcePort() != ConnectionMapper.localTcpServerPort) {
                //readPacket is associated, but the local source port from readpacket
                //differs from the default. For example local TCP clients will
                //use different ports for every connection.
                //This local source port will be updated in the request object.
                request.setLocalTcpPort(readPacket.getSourcePort());
            }
            
            //reconstruct originally connection data
            //For further information
            //please refer to "GatewayConnectionMapper - Sequenzdiagramm.pdf"
            if (request instanceof TcpRequest) {
                //request is a TCP request to a UDP server
                ConnectionMapper.logger.debug("TUN IF: TCP / TCP Request at " + request);
                readPacket.setSourceIP(request.getDestIP());
                readPacket.setSourcePort(request.getDestPort());
                readPacket.setDestIP(request.getSourceIP());
                readPacket.setDestPort(request.getSourcePort());
            } else {
                //request is a UDP request to a TCP server
                ConnectionMapper.logger.debug("TUN IF: TCP / UDP Request at " + request);
                readPacket.setSourceIP(request.getSourceIP());
                readPacket.setSourcePort(request.getLocalTcpPort());
                readPacket.setDestIP(request.getDestIP());
                readPacket.setDestPort(ConnectionMapper.virtualTCPServerPort);
            }
            byte[] encodedPacket = readPacket.encode();
            tun.write(encodedPacket, encodedPacket.length);
        } else if (readPacket.getDestIP().equals(InetAddress.getByName(ConnectionMapper.tunVirtualUdpIP))) {
            //readPacket contains UDP data
            Request request = table.getRequest(readPacket.getDestPort());
            if (request == null) {
                //readPacket cannot be associated to a table entry
                //no information available to restore originally connection data
                ConnectionMapper.logger.error("Unmappable packet on tun if: " + readPacket
                + " Maybe caused by gateway restart?");
                return;
            }
            if (readPacket.getSourcePort() != ConnectionMapper.localUdpServerPort) {
                //readPacket is associated, but the local source port from readpacket
                //differs from the default. For example local TCP clients will
                //use different ports for every connection.
                //This local source port will be updated in the request object.
                request.setLocalUdpPort(readPacket.getSourcePort());
            }
            
            //reconstruct originally connection data
            //For further information
            //please refer to CoAPHTTPGateway - Sequenzdiagramm.pdf
            if (request instanceof UdpRequest) {
                //request is a UDP request to a TCP server
                ConnectionMapper.logger.debug("TUN IF: UDP / UDP Request at " + request);
                readPacket.setSourceIP(request.getDestIP());
                readPacket.setSourcePort(request.getDestPort());
                readPacket.setDestIP(request.getSourceIP());
                readPacket.setDestPort(request.getSourcePort());
            } else {
                //request is a TCP request to a UDP server
                ConnectionMapper.logger.debug("TUN IF: UDP / TCP Request at " + request);
                readPacket.setSourceIP(request.getSourceIP());
                readPacket.setSourcePort(request.getSourcePort());
                readPacket.setDestIP(request.getDestIP());
                readPacket.setDestPort(ConnectionMapper.virtualUDPServerPort);
            }
            byte[] encodedPacket = readPacket.encode();
            tun.write(encodedPacket, encodedPacket.length);
        }
    }    
}
/**
 * This thread reads data from a network interface and sends it after modifying
 * source and destination.
 */
class TcpNetIfPcapThread extends Thread {
    IFReadWriter tun;
    IFReader pcap;
    byte[] blockedSourceMac;

    public TcpNetIfPcapThread(IFReadWriter tun, IFReader pcap,
            byte[] blockedSourceMac) {
        this.tun = tun;
        this.pcap = pcap;
        this.blockedSourceMac = blockedSourceMac;
    }

    @Override
    public void run() {
        byte[] buffer = new byte[1900];
        while (true) {
            try {
                ConnectionMapper.mapTCPNetIF(pcap, buffer, tun, blockedSourceMac);
            } catch (Exception ex) {
                ConnectionMapper.logger.error("TcpNetIfPcapThread: " + ex);
            }
        }
    }
}

/**
 * This thread reads data from a network interface and sends it after modifying
 * source and destination.
 */
class UdpNetIfPcapThread extends Thread {
    IFReadWriter tun;
    IFReader pcap;
    byte[] blockedSourceMac;

    public UdpNetIfPcapThread(IFReadWriter tun, IFReader pcap,
            byte[] blockedSourceMac) {
        this.tun = tun;
        this.pcap = pcap;
        this.blockedSourceMac = blockedSourceMac;
    }

    @Override
    public void run() {
        byte[] buffer = new byte[1900];
        while (true) {
            try {
                ConnectionMapper.mapUDPNetIF(pcap, buffer, tun, blockedSourceMac);
            } catch (Exception ex) {
                ConnectionMapper.logger.error("UdpNetIfPcapThread: " + ex);
            }
        }
    }
}

/**
 * This thread reads data from a network interface and sends it after modifying
 * source and destination.
 */
class TunNetIfThread extends Thread {

    IFReadWriter tun;

    public TunNetIfThread(IFReadWriter tun) {
        this.tun = tun;
    }

    @Override
    public void run() {
        byte[] buffer = new byte[1900];
        while (true) {
            try {
                ConnectionMapper.mapTUNNetIF(tun, buffer);
            } catch (Exception ex) {
                ConnectionMapper.logger.error("TunNetIfThread: " + ex);
            }
        }
    }
}