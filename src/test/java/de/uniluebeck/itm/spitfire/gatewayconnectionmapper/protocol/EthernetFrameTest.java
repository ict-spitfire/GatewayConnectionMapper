/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol;

import java.util.Arrays;
import junit.framework.TestCase;
import static de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol.Tools.*;
/**
 *
 * @author stefan
 */
public class EthernetFrameTest extends TestCase {
    
    public EthernetFrameTest(String testName) {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test of encode method, of class EthernetFrame.
     */
    public void testEncode() throws Exception {
        System.out.println("encode");
        byte[] org = getByteArrayFromString("3333ff0000220800270026c386dd"
                + "6000000000203afffc000000000000000000000000000021ff020000000"
                + "0000000000001ff00002287002b7500000000fc00000000000000000000"
                + "000000002201010800270026c3");
        EthernetFrame instance = new EthernetFrame(org);
        byte[] expResult = copyArray(org);
        byte[] result = instance.encode();
        assertTrue(Arrays.equals(expResult, result));
    }

    /**
     * Test of getDestinationMac method, of class EthernetFrame.
     */
    public void testGetDestinationMac() throws Exception {
        System.out.println("getDestinationMac");
        byte[] org = getByteArrayFromString("3333ff0000220800270026c386dd"
                + "6000000000203afffc000000000000000000000000000021ff020000000"
                + "0000000000001ff00002287002b7500000000fc00000000000000000000"
                + "000000002201010800270026c3");
        EthernetFrame instance = new EthernetFrame(org);
        byte[] expResult = getHWaddrAsBytes("33:33:ff:00:00:22");
        byte[] result = instance.getDestinationMac();
        assertTrue(Arrays.equals(expResult, result));
    }

    /**
     * Test of getSourceMac method, of class EthernetFrame.
     */
    public void testGetSourceMac() throws Exception {
        System.out.println("getSourceMac");
        byte[] org = getByteArrayFromString("3333ff0000220800270026c386dd"
                + "6000000000203afffc000000000000000000000000000021ff020000000"
                + "0000000000001ff00002287002b7500000000fc00000000000000000000"
                + "000000002201010800270026c3");
        EthernetFrame instance = new EthernetFrame(org);
        byte[] expResult = getHWaddrAsBytes("08:00:27:00:26:c3");
        byte[] result = instance.getSourceMac();
        assertTrue(Arrays.equals(expResult, result));
    }

    /**
     * Test of getPayload method, of class EthernetFrame.
     */
    public void testGetPayload() throws Exception {
        System.out.println("getPayload");
        byte[] org = getByteArrayFromString("3333ff0000220800270026c386dd"
                + "6000000000203afffc000000000000000000000000000021ff020000000"
                + "0000000000001ff00002287002b7500000000fc00000000000000000000"
                + "000000002201010800270026c3");
        EthernetFrame instance = new EthernetFrame(org);
        byte[] expResult = getBytes(org, 14, org.length - 14);
        byte[] result = instance.getPayload();
        assertTrue(Arrays.equals(expResult, result));
    }

}
