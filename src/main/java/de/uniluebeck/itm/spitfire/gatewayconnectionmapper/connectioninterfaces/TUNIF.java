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
