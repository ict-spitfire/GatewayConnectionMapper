package de.uniluebeck.itm.spitfire.gatewayconnectionmapper.connectioninterfaces;

/**
 * Interface which has the capability to read data.
 *
 * @author Stefan Hueske
 */
public abstract interface IFReader extends IF {
    /**
     * Reads max nbytes into buffer.
     * @param buffer byte buffer
     * @param nbytes buffer size
     * @return bytes actually read
     */
    public abstract int read(byte[] buffer, int nbytes);
}
