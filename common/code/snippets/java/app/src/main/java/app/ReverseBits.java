package app;

public class ReverseBits {
    public static void main(String args[]) {
        byte input = 11;
        byte mask = 1;
        byte result = 0;
        byte bitsCount = (byte)Math.ceil(Math.sqrt(input));
        for (byte i = 0; i < bitsCount; i++, mask <<= 1) {
            byte maskedBit = (byte)(input & mask);
            System.out.println(String.format("mask=%s maskedBit=%s", mask, maskedBit));
            if (maskedBit == 0) {
                result += mask;
            }
        }
        System.out.println(result);
    }
}

