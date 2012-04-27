package de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol;

import java.net.InetAddress;
import java.util.Arrays;
import junit.framework.TestCase;
import static de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol.Tools.*;
/**
 * Test IPv6 class
 * @author Stefan Hueske
 */
public class IPv6Test extends TestCase {


    public IPv6Test(String testName) {
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
     * Test of encode method, of class IPv6.
     */
    public void testEncode() throws Exception {
        System.out.println("encode");
        byte[] org = getBytes(getByteArrayFromString("0000fffe000000000000000"
                + "0000086dd6000000000280640fc000000000000000000000000000011fc0"
                + "0000000000000000000000000002263d300508f90888700000000a002168"
                + "0dae80000020405a00402080a02b0df8c0"
                + "000000001030306"), 16, 80);
        IPv6Packet instance = new IPv6Packet(org);
        byte[] expResult = Tools.copyArray(org);
        byte[] result = instance.encode();
        assertTrue(Arrays.equals(expResult, result));
    }

    /**
     * Test of getDestIP method, of class IPv6.
     */
    public void testGetDestIP() throws Exception {
        System.out.println("getDestIP");
        byte[] org = getBytes(getByteArrayFromString("0000fffe000000000000000"
                + "0000086dd6000000000280640fc000000000000000000000000000011fc0"
                + "0000000000000000000000000002263d300508f90888700000000a002168"
                + "0dae80000020405a00402080a02b0df8c0"
                + "000000001030306"), 16, 80);
        IPv6Packet instance = new IPv6Packet(org);
        InetAddress expResult = InetAddress.getByName("fc00::22");
        InetAddress result = instance.getDestIP();
        assertEquals(expResult, result);
    }

    /**
     * Test of getDestPort method, of class IPv6.
     */
    public void testGetDestPort() throws Exception {
        System.out.println("getDestPort");
        byte[] org = getBytes(getByteArrayFromString("0000fffe000000000000000"
                + "0000086dd6000000000280640fc000000000000000000000000000011fc0"
                + "0000000000000000000000000002263d300508f90888700000000a002168"
                + "0dae80000020405a00402080a02b0df8c0"
                + "000000001030306"), 16, 80);
        IPv6Packet instance = new IPv6Packet(org);
        int expResult = 80;
        int result = instance.getDestPort();
        assertEquals(expResult, result);
    }

    /**
     * Test of getSourceIP method, of class IPv6.
     */
    public void testGetSourceIP() throws Exception {
        System.out.println("getSourceIP");
        byte[] org = getBytes(getByteArrayFromString("0000fffe000000000000000"
                + "0000086dd6000000000280640fc000000000000000000000000000011fc0"
                + "0000000000000000000000000002263d300508f90888700000000a002168"
                + "0dae80000020405a00402080a02b0df8c0"
                + "000000001030306"), 16, 80);
        IPv6Packet instance = new IPv6Packet(org);
        InetAddress expResult = InetAddress.getByName("fc00::11");
        InetAddress result = instance.getSourceIP();
        assertEquals(expResult, result);
    }

    /**
     * Test of getSourcePort method, of class IPv6.
     */
    public void testGetSourcePort() throws Exception {
        System.out.println("getSourcePort");
        byte[] org = getBytes(getByteArrayFromString("0000fffe000000000000000"
                + "0000086dd6000000000280640fc000000000000000000000000000011fc0"
                + "0000000000000000000000000002263d300508f90888700000000a002168"
                + "0dae80000020405a00402080a02b0df8c0"
                + "000000001030306"), 16, 80);
        IPv6Packet instance = new IPv6Packet(org);
        int expResult = 25555;
        int result = instance.getSourcePort();
        assertEquals(expResult, result);
    }

    /**
     * Test of isTCP method, of class IPv6.
     */
    public void testIsTCP() throws Exception {
        System.out.println("isTCP");
        byte[] tcp = getBytes(getByteArrayFromString("0000fffe000000000000000"
                + "0000086dd6000000000280640fc000000000000000000000000000011fc0"
                + "0000000000000000000000000002263d300508f90888700000000a002168"
                + "0dae80000020405a00402080a02b0df8c0"
                + "000000001030306"), 16, 80);
        IPv6Packet tcpinstance = new IPv6Packet(tcp);

        byte[] udp = getBytes(getByteArrayFromString("0000fffe000000000000"
                + "0000000086dd6000000000291140fc000000000000000000000000000033"
                + "fc000000000000000000000000000031faa98235002980f24501c95b5866"
                + "6330303a3a323221502578616d707002747428b86455026959fe9f"
                + "000000001030306"), 16, 81);
        IPv6Packet udpinstance = new IPv6Packet(udp);

        assertTrue(tcpinstance.isTCP());
        assertFalse(udpinstance.isTCP());
    }

    /**
     * Test of isUDP method, of class IPv6.
     */
    public void testIsUDP() throws Exception {
        System.out.println("isUDP");
        byte[] tcp = getBytes(getByteArrayFromString("0000fffe000000000000000"
                + "0000086dd6000000000280640fc000000000000000000000000000011fc0"
                + "0000000000000000000000000002263d300508f90888700000000a002168"
                + "0dae80000020405a00402080a02b0df8c0"
                + "000000001030306"), 16, 80);
        IPv6Packet tcpinstance = new IPv6Packet(tcp);

        byte[] udp = getBytes(getByteArrayFromString("0000fffe000000000000"
                + "0000000086dd6000000000291140fc000000000000000000000000000033"
                + "fc000000000000000000000000000031faa98235002980f24501c95b5866"
                + "6330303a3a323221502578616d707002747428b86455026959fe9f"
                + "000000001030306"), 16, 81);
        IPv6Packet udpinstance = new IPv6Packet(udp);

        assertFalse(tcpinstance.isUDP());
        assertTrue(udpinstance.isUDP());
    }

    /**
     * Test of getPayload method, of class IPv6.
     */
    public void testGetPayload() throws Exception {
        System.out.println("getPayload");
        byte[] org = getBytes(getByteArrayFromString("0000fffe000000000000000"
                + "0000086dd6000000000280640fc000000000000000000000000000011fc0"
                + "0000000000000000000000000002263d300508f90888700000000a002168"
                + "0dae80000020405a00402080a02b0df8c0"
                + "000000001030306"), 16, 80);
        IPv6Packet instance = new IPv6Packet(org);
        byte[] expResult = getBytes(org, 56-16, 40);
        byte[] result = instance.getPayload();
        assertTrue(Arrays.equals(expResult, result));
    }

    /**
     * Test of getNextHeader method, of class IPv6.
     */
    public void testGetNextHeader() throws Exception {
        System.out.println("getNextHeader");
        byte[] org = getBytes(getByteArrayFromString("0000fffe000000000000000"
                + "0000086dd6000000000280640fc000000000000000000000000000011fc0"
                + "0000000000000000000000000002263d300508f90888700000000a002168"
                + "0dae80000020405a00402080a02b0df8c0"
                + "000000001030306"), 16, 80);
        IPv6Packet instance = new IPv6Packet(org);
        int expResult = 6;
        int result = instance.getNextHeader();
        assertEquals(expResult, result);
    }
}
