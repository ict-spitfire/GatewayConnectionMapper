package de.uniluebeck.itm.spitfire.gatewayconnectionmapper.connectioninterfaces;

import de.uniluebeck.itm.spitfire.gatewayconnectionmapper.ConnectionMapper;
import java.io.IOException;
import java.util.Date;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

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
            ConnectionMapper.logger.error("Error while opening device for capture: "
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