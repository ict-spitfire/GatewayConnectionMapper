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
package de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol;

import java.util.Arrays;
import junit.framework.TestCase;

/**
 * Test basic byte operations
 * @author Stefan Hueske
 */
public class ToolsTest extends TestCase {

    public ToolsTest(String testName) {
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
     * Test of getBytesAsString method, of class Tools.
     */
    public void testGetBytesAsString_byteArr_int() {
        System.out.println("getBytesAsString");
        byte[] data = {0x01, (byte) 0xFF};
        int n = 2;
        String expResult = " \n01 ff ";
        String result = Tools.getBytesAsString(data, n);
        assertEquals(expResult, result);
    }

    /**
     * Test of getByteAsString method, of class Tools.
     */
    public void testGetByteAsString() {
        System.out.println("getByteAsString");

        byte b = 0x12;
        String expResult = "12";
        String result = Tools.getByteAsString(b);
        assertEquals(expResult, result);

        b = 0x00;
        expResult = "00";
        result = Tools.getByteAsString(b);
        assertEquals(expResult, result);

        b = (byte) 0xFF;
        expResult = "ff";
        result = Tools.getByteAsString(b);
        assertEquals(expResult, result);
    }

    /**
     * Test of getBytes method, of class Tools.
     */
    public void testGetBytes() throws Exception {
        System.out.println("getBytes");
        byte[] data = {0x01, (byte) 0xFF, 0x34};
        int index = 1;
        int length = 2;
        byte[] expResult = {(byte) 0xFF, 0x34};
        byte[] result = Tools.getBytes(data, index, length);
        assertTrue(Arrays.equals(expResult, result));
    }

    /**
     * Test of getHWaddrAsBytes method, of class Tools.
     */
    public void testGetHWaddrAsBytes() throws Exception {
        System.out.println("getHWaddrAsBytes");
        String hwAddr = "08:00:27:7d:d2:cc";
        byte[] expResult = {0x08, 0x00, 0x27, 0x7d, (byte) 0xd2, (byte) 0xcc};
        byte[] result = Tools.getHWaddrAsBytes(hwAddr);
        assertTrue(Arrays.equals(expResult, result));
    }

    /**
     * Test of getHWaddrAsString method, of class Tools.
     */
    public void testGetHWaddrAsString() throws Exception {
        System.out.println("getHWaddrAsString");
        byte[] hwAddr = {0x08, 0x00, 0x27, 0x7d, (byte) 0xd2, (byte) 0xcc};
        String expResult = "08:00:27:7d:d2:cc";
        String result = Tools.getHWaddrAsString(hwAddr);
        assertEquals(expResult, result);
    }

    /**
     * Test of add16bitOnesComplement method, of class Tools.
     */
    public void testAdd16bitOnesComplement() {
        System.out.println("add16bitOnesComplement");
        int i1 = 0x0000FFFF;
        int i2 = 0x00000010;
        int expResult = 0x00000010;
        int result = Tools.add16bitOnesComplement(i1, i2);
        assertEquals(expResult, result);
    }

    /**
     * Test of byteArrayEquals method, of class Tools.
     */
    public void testByteArrayEquals() {
        System.out.println("byteArrayEquals");
        byte[] b1 = {0x08, 0x00, 0x27, 0x7d, (byte) 0xd2, (byte) 0xcc};
        byte[] b2 = {0x08, 0x00, 0x27, 0x7d, (byte) 0xd2, (byte) 0xcc};
        boolean expResult = true;
        boolean result = Tools.byteArrayEquals(b1, b2);
        assertEquals(expResult, result);

        byte[] b3 = {0x08, 0x01, 0x27, 0x7d, (byte) 0xd2, (byte) 0xcc};
        expResult = false;
        result = Tools.byteArrayEquals(b1, b3);
        assertEquals(expResult, result);
    }

    /**
     * Test of getBytesFromInt method, of class Tools.
     */
    public void testGetBytesFromInt() {
        System.out.println("getBytesFromInt");
        int val = 515515151;
        byte[] expResult = {0x1E, (byte) 0xBA, 0x23, 0x0F};
        byte[] result = Tools.getBytesFromInt(val);
        assertTrue(Arrays.equals(expResult, result));
    }

    /**
     * Test of getUnsignedInt method, of class Tools.
     */
    public void testGetUnsignedInt() {
        System.out.println("getUnsignedInt");
        byte[] b = {0x12, 0x34};
        int expResult = 4660;
        int result = Tools.getUnsignedInt(b);
        assertEquals(expResult, result);
    }

    /**
     * Test of insertBytes method, of class Tools.
     */
    public void testInsertBytes() throws Exception {
        System.out.println("insertBytes");
        byte[] data = {0x08, 0x00, 0x27, 0x7d, (byte) 0xd2, (byte) 0xcc};
        byte[] toInsert = {0x11, 0x22};
        int index = 2;
        int length = 3;
        Tools.insertBytes(data, toInsert, index, length);
        byte[] result = {0x08, 0x00, 0x00, 0x11, (byte) 0x22, (byte) 0xcc};
        assertTrue(Arrays.equals(data, result));
    }

    /**
     * Test of copyArray method, of class Tools.
     */
    public void testCopyArray() {
        System.out.println("copyArray");
        byte[] b = {0x08, 0x00, 0x27, 0x7d, (byte) 0xd2, (byte) 0xcc};
        byte[] result = Tools.copyArray(b);
        assertNotSame(b, result);
        assertTrue(Arrays.equals(b, result));
    }
}
