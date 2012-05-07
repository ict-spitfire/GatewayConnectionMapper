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

import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol.IPv6Packet;

import java.net.InetAddress;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

/**
 * This class manages and offers all information to map connections
 * to a unique port and restore them.
 *
 * @author Stefan Hueske
 */
public class ConnectionTable {

    /*
     * In this context a 'Request' is a combination of
     * two address port pairs. TCP Request means that the connection was
     * initiated by a TCP client and is not dependent on the packets payload.
     * A 'Response' (eg. UDPResponseForTCPRequest) describes the inversion of
     * source and client pair.
     * UDPResponseForTCPRequest => is a UDP packet
     * TCPResponseForUDPRequest => is a TCP packet
     * To comprehend the mapping mechanism have a look at the
     * enclosed sequence diagram.
     * "GatewayConnectionMapper - Sequenzdiagramm.pdf"
     */

    //List of TCP requests
    private List<Request> tcpRequests = new LinkedList<Request>();

    //List of UDP requests
    private List<Request> udpRequests = new LinkedList<Request>();
    
    //ListCleaner removes outdated requests from both lists
    private ListCleaner listCleaner = new ListCleaner(this);
    
    //singleton
    private static ConnectionTable instance;
    Random random = new Random();

    private ConnectionTable() {
        listCleaner.start();
    }
    /**
     * Get a instance.
     * @return Global ConnectionTable instance
     */
    public static ConnectionTable getInstance() {
        if (instance == null) {
            instance = new ConnectionTable();
        }
        return instance;
    }

    /**
     * Map a incoming TCP request.
     * @param packet IPv6Packet packet
     * @return unique local port ('mapped port')
     */
    public int mapTcpRequest(IPv6Packet packet) {
        return mapRequest(tcpRequests, packet, true);
    }
    
    /**
     * Map a incoming UDP request.
     * @param packet IPv6Packet packet
     * @return unique local port ('mapped port')
     */
    public int mapUdpRequest(IPv6Packet packet) {
        return mapRequest(udpRequests, packet, false);
    }

    /**
     * Get mapped port for a tcp request.
     * @param packet IPv6Packet packet
     * @return unique local port ('mapped port') if exists, -1 else
     */
    public int getMappedPortFromTcpRequest(IPv6Packet packet) {
        return getMappedPortFromRequest(tcpRequests, packet);
    }

    /**
     * Get mapped port for a udp request.
     * @param packet IPv6Packet packet
     * @return unique local port ('mapped port') if exists, -1 else
     */
    public int getMappedPortFromUdpRequest(IPv6Packet packet) {
        return getMappedPortFromRequest(udpRequests, packet);
    }

    /**
     * Get mapped port for a UDPResponse for a TCPRequest.
     * @param packet IPv6Packet packet
     * @return unique local port ('mapped port') if exists, -1 else
     */
    public int getMappedPortFromUDPResponseForTCPRequest(IPv6Packet packet) {
        return getMappedPortFromResponse(tcpRequests, packet);
    }

    /**
     * Get mapped port for a TCPResponse for a UDPRequest.
     * @param packet IPv6Packet packet
     * @return unique local port ('mapped port') if exists, -1 else
     */
    public int getMappedPortFromTCPResponseForUDPRequest(IPv6Packet packet) {
        UdpRequest orgRequest = getUDPRequestFromLocalTcpPort(packet.getDestPort());
        if (orgRequest == null) {
            return -1;
        }
        int orgDestPort = packet.getDestPort();
        packet.setDestPort(orgRequest.getSourcePort());
        int mappedPort = getMappedPortFromResponse(udpRequests, packet);
        packet.setDestPort(orgDestPort);
        return mappedPort;
    }

    /**
     * Get a UdpRequest from the local TCP port, which is only unique to
     * all UdpRequests.
     * @param localTcpPort local TCP port
     * @return UdpRequest if exists, null else
     */
    private UdpRequest getUDPRequestFromLocalTcpPort(int localTcpPort) {
        for (Request request : udpRequests) {
            UdpRequest udpRequest = (UdpRequest) request;
            if (udpRequest.getLocalTcpPort() == localTcpPort) {
                return udpRequest;
            }
        }
        return null;
    }

    /**
     * Get a TcpRequest from a mapped port.
     * @param mappedPort mapped port
     * @return TcpRequest if exists, null else
     */
    public TcpRequest getTcpRequest(int mappedPort) {
        return (TcpRequest) getRequest(tcpRequests, mappedPort);
    }

    /**
     * Get a UdpRequest from a mapped port.
     * @param mappedPort mapped port
     * @return UdpRequest if exists, null else
     */
    public UdpRequest getUdpRequest(int mappedPort) {
        return (UdpRequest) getRequest(udpRequests, mappedPort);
    }

    /**
     * Get a Udp or Tcp Request from a mapped port.
     * Do not use this function if you already know
     * which type you are searching for.
     * @param mappedPort mapped port
     * @return Request object instanceof UdpRequest or TcpRequest (if exists, null else)
     */
    public Request getRequest(int mappedPort) {
        Request request = getTcpRequest(mappedPort);
        if (request != null) {
            return request;
        }
        request = getUdpRequest(mappedPort);
        if (request != null) {
            return request;
        }
        return null;
    }
    
    /**
     * Map a request. This means: Looking if the request already exists if
     * not, a new entry will be generated.
     * @param requestList TCP or UDP request list
     * @param packet IPv6Packet packet
     * @param isTCP true if it is the TCP request list
     * @return mapped port
     */
    private synchronized int mapRequest(List<Request> requestList, IPv6Packet packet,
            boolean isTCP) {
        int port = getMappedPortFromRequest(requestList, packet);
        if (port == -1) {
            port = getFreePort();
            requestList.add(isTCP ? new TcpRequest(packet, port) : new UdpRequest(packet, port));
        }
        return port;
    }

    /**
     * 
     * @param requestList
     * @param packet
     * @return 
     */
    private synchronized static int getMappedPortFromRequest(List<Request> requestList,
            IPv6Packet packet) {
        for (Request r : requestList) {
            if (r.getSourcePort() == packet.getSourcePort() &&
                    r.getSourceIP().equals(packet.getSourceIP()) &&
                    r.getDestIP().equals(packet.getDestIP()) ) {
                r.updateLastUsed();
                return r.getMappedPort();
            }
        }
        return -1;
    }

    private synchronized static int getMappedPortFromResponse(List<Request> list,
            IPv6Packet p) {
        for (Request r : list) {
            if (r.getSourceIP().equals(p.getDestIP()) &&
                    r.getSourcePort() == p.getDestPort() &&
                    r.getDestIP().equals(p.getSourceIP()) ) {
                r.updateLastUsed();
                return r.getMappedPort();
            }
        }
        return -1;
    }


    private synchronized static Request getRequest(List<Request> list,
            int mappedPort) {
        for (Request r : list) {
            if (r.getMappedPort() == mappedPort) {
                return r;
            }
        }
        return null;
    }

    private synchronized int getFreePort() {
        int res;
        do {
            res = (int) (Math.random() * 65535 + 1);
        } while(!isFreePort(res));
        return res;
    }

    private synchronized boolean isFreePort(int port) {
        return getRequest(tcpRequests, port) == null &&
                getRequest(udpRequests, port) == null;
    }

    /**
     * This class represents a mapped connection, containing all
     * associated information to identify packets on all three
     * network interfaces.
     */
    public static abstract class Request {
        //timeout in ms, until this connection can be removed
        public static long TIMEOUT = 30000;

        //unique port, will be used as source port
        //for packets send by the tun IF
        int mappedPort;

        //Connection information
        InetAddress sourceIP;
        int sourcePort;
        InetAddress destIP;
        int destPort;

        //last used (system time in ms)
        long lastUsed;

        //this port is set when the local gateway socket creates a new TCP/UDP
        //connection on a new port, otherwise it will be the local TCP/UDP
        //server port.
        int localTcpPort = ConnectionMapper.localTcpServerPort;
        int localUdpPort = ConnectionMapper.localUdpServerPort;

        /**
         * Create a new Request.
         * @param mappedPort
         * @param sourceIP
         * @param sourcePort
         * @param destIP
         * @param destPort
         */
        public Request(int mappedPort, InetAddress sourceIP, int sourcePort,
                InetAddress destIP, int destPort) {
            this.mappedPort = mappedPort;
            this.sourceIP = sourceIP;
            this.sourcePort = sourcePort;
            this.destIP = destIP;
            this.destPort = destPort;
            lastUsed = System.currentTimeMillis();
        }

        /**
         * Create a new Request. Source/Dest. IP and Port will be copied from
         * the passed IPv6Packet packet.
         * @param p IPv6Packet packet
         * @param mappedPort
         */
        public Request(IPv6Packet p, int mappedPort) {
            this(mappedPort, p.getSourceIP(), p.getSourcePort(), p.getDestIP(), p.getDestPort());
        }

        
        @Override
        public String toString() {
            StringBuilder s = new StringBuilder();
            s.append("port ").append(mappedPort).append(": ");
            s.append(sourceIP.getHostAddress()).append(":").append(sourcePort).append(" -> ");
            s.append(destIP.getHostAddress()).append(":").append(destPort);
            return s.toString();
        }

        /**
         * Get the destination IP.
         * @return IPv6Packet IP
         */
        public InetAddress getDestIP() {
            return destIP;
        }

        /**
         * Get the destination port.
         * @return port as integer
         */
        public int getDestPort() {
            return destPort;
        }

        /**
         * Get the time when this Request object was last used.
         * @return time as long (system time)
         */
        public long getLastUsed() {
            return lastUsed;
        }

        /**
         * Get the unique local mapped port.
         * @return port as integer
         */
        public int getMappedPort() {
            return mappedPort;
        }

        /**
         * Get the source IP.
         * @return IPv6Packet IP
         */
        public InetAddress getSourceIP() {
            return sourceIP;
        }

        /**
         * Get the source port.
         * @return port as integer
         */
        public int getSourcePort() {
            return sourcePort;
        }

        /**
         * Get the local TCP port,
         * which will be used to communicate with the gateways TCP socket.
         * @return port as integer
         */
        public int getLocalTcpPort() {
            return localTcpPort;
        }

        /**
         * Set the local TCP port,
         * which will be used to communicate with the gateways TCP socket.
         */
        public void setLocalTcpPort(int localTcpPort) {
            this.localTcpPort = localTcpPort;
        }

        /**
         * Get the local UDP port,
         * which will be used to communicate with the gateways UDP socket.
         * @return port as integer
         */
        public int getLocalUdpPort() {
            return localUdpPort;
        }

        /**
         * Set the local UDP port,
         * which will be used to communicate with the gateways UDP socket.
         */
        public void setLocalUdpPort(int localUdpPort) {
            this.localUdpPort = localUdpPort;
        }

        /*
         * Update the lastUsed value. This will 'reset' the timeout.
         */
        public void updateLastUsed() {
            lastUsed = System.currentTimeMillis();
        }

        /**
         * Check if this request is outdated.
         * @return true if outdated, false else.
         */
        public boolean isTimedOut() {
            return (System.currentTimeMillis() - lastUsed > TIMEOUT) ? true : false;
        }
    }

    /**
     * This class represents a TCP request.
     * @see Request
     */
    public static class TcpRequest extends Request {

        public TcpRequest(int mappedPort, InetAddress sourceIP, int sourcePort,
                InetAddress destIP, int destPort) {
            super(mappedPort, sourceIP, sourcePort, destIP, destPort);
        }
        
        public TcpRequest(IPv6Packet p, int mappedPort) {
            super(p, mappedPort);
        }
        
    }

    /**
     * This class represents a UDP request.
     * @see Request
     */
    public static class UdpRequest extends Request {

        private UdpRequest(int mappedPort, InetAddress sourceIP, int sourcePort,
                InetAddress destIP, int destPort) {
            super(mappedPort, sourceIP, sourcePort, destIP, destPort);
        }

        public UdpRequest(IPv6Packet p, int mappedPort) {
            super(p, mappedPort);
        }

    }

    /**
     * Remove all outdated items in list.
     * @param list list to check
     */
    private static synchronized void cleanList(List<Request> list) {
        for (int i = list.size() - 1; i >= 0; i--) {
            Request r = list.get(i);
            if (r.isTimedOut()) {
                list.remove(i);
                ConnectionMapper.log.debug("TABLE: Connection timed out: " + r);
            }
        }
    }

    /**
     * This thread removes outdated items.
     */
    public static class ListCleaner extends Thread {
        ConnectionTable table;

        public ListCleaner(ConnectionTable table) {
            this.table = table;
        }

        public static int INTERVALL = 10000; //in ms
        @Override
        public void run() {
            while (true) {
                try {
                    cleanList(table.tcpRequests);
                    cleanList(table.udpRequests);
                    Thread.sleep(INTERVALL);
                } catch (InterruptedException ex) {
                    ConnectionMapper.log.fatal("Exception in List cleaner: " + ex);
                }
            }
        }

    }
}
