package de.uniluebeck.itm.spitfire.gatewayconnectionmapper.protocol;

/**
 * This class contains a set of tools to manipulate and demonstrate binary
 * (byte based) data.
 * @author Stefan Hueske
 */
public class Tools {

    /**
     * Returns human friendly hex string representation of a passed byte array.
     * (The same formatting wireshark uses)
     * @param data Data as byte array
     * @param n Only the first n bytes from data will be read
     * @return Formatted hex string
     */
    public static String getBytesAsString(byte[] data, int n) {
        StringBuilder res = new StringBuilder();

        for (int i = 0; i < n; i++) {
            if (i % 8 == 0) {
                res.append(" ");
            }
            if (i % 16 == 0) {
                res.append("\n");
            }
            byte b = data[i];
            int b1 = (b >> 4) & 0x0F;
            int b2 = b & 0x0F;
            res.append(Integer.toString(b1, 16));
            res.append(Integer.toString(b2, 16));
            res.append(" ");
        }

        return res.toString();
    }

    /**
     * Returns the hex representation of a single byte.
     * @param b Byte to convert
     * @return Hex value of b
     */
    public static String getByteAsString(byte b) {
        int b1 = (b >> 4) & 0x0F;
        int b2 = b & 0x0F;
        return Integer.toString(b1, 16) + Integer.toString(b2, 16);
    }

    /**
     * Returns human friendly hex string representation of a passed byte array.
     * (The same formatting wireshark uses)
     * @param data Data as byte array
     * @return Formatted hex string
     */
    public static String getBytesAsString(byte[] data) {
        return getBytesAsString(data, data.length);
    }

    /**
     * Returns a subset of a passed byte array.
     * @param data Data as byte array
     * @param index Index in data for the first byte in the subset
     * @param length Subset length
     * @return Subset as byte array
     * @throws Exception will be thrown when the specified subset is invalid
     */
    public static byte[] getBytes(byte[] data, int index, int length) throws Exception {
//        System.out.println("data len: " + data.length);
//        System.out.println("index   : " + index);
//        System.out.println("length  : " + length);
        byte[] res = new byte[length];
        for (int i = 0; i < length; i++) {
            res[i] = data[i + index];
        }
        return res;
    }

    /**
     * Returns the passed MAC/hardware address as byte arrary.
     * @param hwAddr MAC/HWaddr as String
     * @return Converted MAC/HWaddr as byte array
     * @throws Exception Will be thrown when the passed hwAddr is invalid
     */
    public static byte[] getHWaddrAsBytes(String hwAddr) throws Exception {
        String a = hwAddr.replace(":", "");
        a = a.replace(" ", "");

        if (a.length() != 12) {
            throw new Exception("Invalid mac address: " + a);
        }

        byte[] res = new byte[6];

        for (int i = 0; i < 6; i++) {
            String c = a.substring(i * 2, i * 2 + 1);
            byte b1 = Byte.parseByte(c, 16);
            c = a.substring(i * 2 + 1, i * 2 + 2);
            byte b2 = Byte.parseByte(c, 16);
            res[i] = (byte) ((b1 << 4) + b2);
        }

        return res;
    }

    /**
     * Returns the passed MAC/hardware address as String.
     * @param hwAddr hwAddr MAC/HWaddr as byte array
     * @return Converted MAC/HWaddr as String
     * @throws Exception Will be thrown when the passed hwAddr is invalid
     */
    public static String getHWaddrAsString(byte[] hwAddr) throws Exception {
        if (hwAddr.length != 6) {
            throw new Exception("Invalid mac address: " + getBytesAsString(hwAddr));
        }
        StringBuilder res = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i != 0) {
                res.append(":");
            }
            res.append(getByteAsString(hwAddr[i]));
        }
        return res.toString();
    }

    /*public static void main(String[] args) throws Exception {
        String s = "60 00 00 00 00 28 06 40  fc 00 00 00 00 00 00 0000 00 00 00 00 00 00 22  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 11  d2 2d 1f 90 cf ec c7 7600 00 00 00 a0 02 16 80  e6 d8 00 00 02 04 05 a0 04 02 08 0a 00 44 c9 22  00 00 00 00 01 03 03 06";
        String s = "080027248bea080027a7fe7686dd6000000000281140fc000000000000000000000000000012fc0000000000000000000000000000118235115c0028bf54450112b5110048666330303a3a313122115c2474657374282bcfd809e5840bef";
        System.out.println("Checksum: bf 54");
                String s = "080027248bea080027a7fe7686dd600000000020063ffc000000000000000000000000000022fc000000000000000000000000000011d8581f915584bfaa570febaa8011005a174800000101080a008a070d008a0ef2";
        byte[] ethfrB = getByteArrayFromStringDebug(s);
        EthernetFrame ethfr = new EthernetFrame(ethfrB);
        IPv6 ipv6 = new IPv6(ethfr.getPayload());
        byte[] ipv6B = ipv6.encode();
        byte[] checksum = getBytes(ethfrB, 70, 2);
        System.out.println("Org : " + getBytesAsString(checksum));
        System.out.println("Calc: " + getBytesAsString(calculateUDPchecksum(ipv6)));

        byte[] b1 = {(byte)0xFF, (byte)0xFF};
        byte[] b2 = {(byte)0xFF, (byte)0xFF};
        System.out.println(getBytesAsString(getBytesFromInt(72)));
        System.out.println("b:" + getBytesAsString(b1));
        System.out.println("calctest:" + getBytesAsString(getBytesFromInt(add16bitOnesComplement(getUnsignedInt(b1),getUnsignedInt(b2)))));
    }*/

    /**
     * Returns the result of adding i1 and i2, both interpreted as
     * 16 bit ones' complement.
     * @param i1 16 bit ones' complement first addend
     * @param i2 16 bit ones' complement second addend
     * @return 16 bit ones' complement addition result
     */
    public static int add16bitOnesComplement(int i1, int i2) {
//        System.out.println("Zahl:" + i1);
        int res = i1 + i2;
        int uebertrag = res >> 16;
//        System.out.println("Uebertrag: " + uebertrag);
//          System.out.println("masked res: " + res);
        res += uebertrag;
        res = res & 0x0000FFFF;
//
//        System.out.println("Result: " + res);
        return res;
    }

    /**
     * Tests if both passed byte arrays are equal.
     * @param b1 First byte array
     * @param b2 Second byte array
     * @return True if equal, false else
     */
    public static boolean byteArrayEquals(byte[] b1, byte[] b2) {
        if (b1.length != b2.length) {
            return false;
        }
        for (int i = 0; i < b1.length; i++) {
            if (b1[i] != b2[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Converts an unsigned int into a byte array.
     * @param val Unsigned int to convert
     * @return Converted value as (unsigned) byte array
     */
    public static byte[] getBytesFromInt(int val) {
        String s = Integer.toHexString(val);
        if (s.length() % 2 != 0) {
            s = "0" + s;
        }
        byte[] res = new byte[s.length() / 2];
        for (int i = 0; i < s.length() / 2; i++) {
            String c = s.substring(i * 2, i * 2 + 1);
            byte b1 = Byte.parseByte(c, 16);
            c = s.substring(i * 2 + 1, i * 2 + 2);
            byte b2 = Byte.parseByte(c, 16);
            res[i] = (byte) ((b1 << 4) + b2);
        }
        return res;
    }
    
    /**
     * Converts a (unsigned) byte array into an int.
     * @param b Byte array to convert
     * @return Converted byte array as int
     */
    public static int getUnsignedInt(byte[] b) {
        if (b.length == 0) {
            return 0;
        }
        if (b.length <= 3) {
            return getUnsignedIntForShortValues(b);
        }
        StringBuilder r = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            r.append(getByteAsString(b[i]));
        }
        return Integer.parseInt(r.toString(), 16);
    }
    
    private static int getUnsignedIntForShortValues(byte[] b) {
        //This version for <= 3 bytes is much faster
        int r = (int)b[0] & 0xFF;
        for (int i = 1; i < b.length; i++) {
            r = r << 8;
            r += (int)b[i] & 0xFF;
        }
        return r;
    }

    /**
     * Inserts an array of bytes into data. All fields from
     * data[index] to data[index + length - 1] will overwritten by
     * toInsert or set to zero if toInsert.length is less length.
     * @param data Data to insert into
     * @param toInsert Data to insert
     * @param index Starting index in data
     * @param length length in data
     * @throws Exception will be thrown if insertion fails.
     */
    public static void insertBytes(byte[] data, byte[] toInsert, int index, int length) throws Exception {
        for (int i = 0; i < length; i++) {
            data[i + index] = 0x00;
        }
        if (length < toInsert.length) {
            toInsert = getBytes(toInsert, 0, length);
        }
        for (int i = 0; i < toInsert.length; i++) {
            data[index + length - toInsert.length + i] = toInsert[i];
        }
    }

    /**
     * Returns a hex interpretation of String s as byte array.
     * @param s String to convert
     * @return Converted String as byte array
     */
    public static byte[] getByteArrayFromString(String s) {
        s = s.replace(" ", "");
        s = s.replace("\n", "");
        byte[] res = new byte[s.length() / 2];
        for (int i = 0; i < s.length() / 2; i++) {
            String c = s.substring(i * 2, i * 2 + 1);
            byte b1 = Byte.parseByte(c, 16);
            c = s.substring(i * 2 + 1, i * 2 + 2);
            byte b2 = Byte.parseByte(c, 16);
            res[i] = (byte) ((b1 << 4) + b2);
        }
        return res;
    }

    /**
     * Returns a copy of the passed byte array.
     * @param b Byte array to copy
     * @return Copy of b
     */
    public static byte[] copyArray(byte[] b) {
        byte[] res = new byte[b.length];
//        for (int i = 0; i < b.length; i++) {
//            res[i] = b[i];
//        }
        System.arraycopy(b, 0, res, 0, b.length);
        return res;
    }

    /**
     * Compares two byte arrays and shows differences very "human friendly".
     * @param b1
     * @param b2
     * @return Formatted comparison as String
     * @throws Exception
     */
    public static String compareBytes(byte[] b1, byte[] b2) throws Exception {
        if (b1.length != b2.length) {
            throw new Exception("Both arrays must have the same length");
        }
        byte[] c1 = copyArray(b1);
        byte[] c2 = copyArray(b2);

        StringBuilder r1 = new StringBuilder("1st bytearray:");
        StringBuilder r2 = new StringBuilder("\n\n2nd bytearray:");

        for (int i = 0; i < b1.length; i++) {
            if (i % 8 == 0) {
                r1.append(" ");
                r2.append(" ");
            }
            if (i % 16 == 0) {
                r1.append("\n");
                r2.append("\n");
            }
            if (c1[i] == c2[i]) {
                r1.append("-- ");
                r2.append("-- ");
            } else {
                byte b = c1[i];
                int i1 = (b >> 4) & 0x0F;
                int i2 = b & 0x0F;
                r1.append(Integer.toString(i1, 16));
                r1.append(Integer.toString(i2, 16));
                r1.append(" ");
                b = c2[i];
                i1 = (b >> 4) & 0x0F;
                i2 = b & 0x0F;
                r2.append(Integer.toString(i1, 16));
                r2.append(Integer.toString(i2, 16));
                r2.append(" ");
            }
            
        }
        r1.append(r2);
        return r1.toString();

    }
}
