package de.uniluebeck.itm.spitfire.gatewayconnectionmapper.connectioninterfaces;

/**
 * Interface which has the capability to write data.
 * @author Stefan Hueske
 */
public abstract interface IFWriter extends IF {
    /**
     * Writes nbytes from buffer.
     * @param buffer byte buffer with data
     * @param nbytes number of bytes which should be written from buffer
     * @return bytes actually written
     */
    public abstract int write(byte[] buffer, int nbytes);
}