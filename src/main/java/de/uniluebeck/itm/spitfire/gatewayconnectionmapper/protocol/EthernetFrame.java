package de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol;

import static de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol.Tools.*;

/**
 * This class represents a ethernet frame.
 * Payload, destination and source data can be modified and re-encoded again.
 * @author Stefan Hueske
 */
public class EthernetFrame {
    byte[] payload;
    byte[] destinationMac;
    byte[] sourceMac;
    byte[] type;

    //
    public static final byte[] IPv6_TYPE = getByteArrayFromString("86dd");

    /**
     * Create a new instance by decoding a passed ethernet frame.
     * @param data Ethernet frame as byte array
     * @throws Exception Will be thrown when decoding fails
     */
    public EthernetFrame(byte[] data) throws Exception {
        payload = getBytes(data, 14, data.length - 14);
        destinationMac = getBytes(data, 0, 6);
        sourceMac = getBytes(data, 6, 6);
        type = getBytes(data, 12, 2);
    }

    /**
     * Create a new instance by decoding a passed ethernet frame.
     * @param data Ethernet frame as byte array
     * @param n Reads only the first n bytes from data
     * @throws Exception Exception Will be thrown when decoding fails
     */
    public EthernetFrame(byte[] data, int n) throws Exception {
        this(getBytes(data, 0, n));
    }

    /**
     * Encode this ethernet frame to a byte array.
     * @return Encoded ethernet frame
     * @throws Exception Will be thrown when encoding fails
     */
    public byte[] encode() throws Exception {
        byte[] res = new byte[payload.length + destinationMac.length
                + sourceMac.length + type.length];
        insertBytes(res, payload, 14, payload.length);
        insertBytes(res, destinationMac, 0, 6);
        insertBytes(res, sourceMac, 6, 6);
        insertBytes(res, type, 12, 2);
        return res;
    }

    /**
     * Sets a new destination mac address
     * @param destinationMac Destination address as byte array
     */
    public void setDestinationMac(byte[] destinationMac) {
        this.destinationMac = destinationMac;
    }

    /**
     * Sets a new source mac address
     * @param sourceMac Source address as byte array
     */
    public void setSourceMac(byte[] sourceMac) {
        this.sourceMac = sourceMac;
    }

    /**
     * Returns the destination mac as byte array
     * @return Destination mac as byte array
     */
    public byte[] getDestinationMac() {
        return destinationMac;
    }

    /**
     * Returns the source mac as byte array
     * @return Source mac as byte array
     */
    public byte[] getSourceMac() {
        return sourceMac;
    }

    /**
     * Returns the payload as byte array
     * @return Payload as byte array
     */
    public byte[] getPayload() {
        return payload;
    }

    /**
     * Sets the payload for this ethernet frame
     * @param payload New payload as byte array
     */
    public void setPayload(byte[] payload) {
        this.payload = payload;
    }

    @Override
    public String toString() {
        try {
            return "Ethernet: " + getHWaddrAsString(sourceMac) + " -> " + getHWaddrAsString(destinationMac);
        } catch (Exception ex) {
            return ex.toString();
        }
    }

    /**
     * Returns true if type is 0x86DD.
     * @return True if IPv6, false else
     */
    public boolean isIPv6() {
        return byteArrayEquals(type, IPv6_TYPE);
    }
}
