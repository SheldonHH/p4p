/**
 * Copyright (c) 2007 Regents of the University of California.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the University may not be used to endorse or promote products 
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

package p4p.util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import net.i2p.util.NativeBigInteger;

public class Util extends P4PParameters {
    public static SecureRandom rand = new SecureRandom();
    
    // Warming up:
    static {
        rand.nextBoolean();
    }
    
    private static int close_t_uniform_q_minus_1 = 20;
    /**
     * This parameter controls how "close" our random numbers generated by the 
     * following two functions are to a true uniform distribution over 
     * [0, ..., q-1). We essentially generate t more random bites and do mod q. 
     * The statisical distance to a true uniform distribution is 2^{-t}. See 
     * 
     *   Victor Shoup, A Computational Introduction to Number Theory 
     *   and Algebra, pp 157. http://www.shoup.net/ntb/
     */

    /**
     * Randomly generates a <code>BigInteger</code> between 1 to n-1, inclusive. 
     * 
     * @param	set_size	the size of the set
     * @return	a BigInteger uniformly randomly distributed between [1, n-1]
     */
    public static BigInteger randomBigInteger(BigInteger set_size) {
        while(true) {
            BigInteger r = new BigInteger(set_size.bitLength()+close_t_uniform_q_minus_1, rand);
            if(!r.equals(BigInteger.ZERO))
                return r.mod(set_size);
        }
    }


    /**
     * A hash function mapping the message to an element in Z_q. We just 
     * compute SHA-512 hash of the messages and catenate them until we have 
     * enough bits.
     *
     * @param	msg	the array of messages
     * @param	q	the size of the set
     * @return	an element in Z_q which is a hash of the given messages.
     *
     */
    public static BigInteger secureHash(BigInteger[] msg, BigInteger size_set_secureHash)
        throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        final int HASH_LENGTH = md.getDigestLength();  
        // The length of the hash in bytes
        int k = size_set_secureHash.bitLength()+1;
        // The required length of output in bits
        
        int nRounds = k/(HASH_LENGTH*8+close_t_uniform_q_minus_1)+1;
        byte[] hash = new byte[HASH_LENGTH*nRounds];
        
        for(int i = 0; i < nRounds; i++) {
            md.reset();
            for(int j = 0; j < msg.length; j++)
                md.update(msg[j].toByteArray());  // hash all the messages
            
            md.update((byte)i);  // Also include the current index
            md.digest(hash, i*HASH_LENGTH, HASH_LENGTH);
        }
        
        // Now we got all the bits. Make a BigInteger out of it:
        return new BigInteger(hash).mod(size_set_secureHash);
    }
    

    /**
     * Converts a short into its little-endian byte string representation.
     *
     * @param	array	the array in which to store the byte string.
     * @param	offset	the offset in the array where the string will start.
     * @param	value	the value to convert.
     */
    public static void bytesFromShort(byte[] array, int offset, short value) {
        array[offset+0] = (byte) ((value>>0)&0xFF);
        array[offset+1] = (byte) ((value>>8)&0xFF);
    }
    
    /**
     * Converts an int into its little-endian byte string representation.
     *
     * @param	array	the array in which to store the byte string.
     * @param	offset	the offset in the array where the string will start.
     * @param	value	the value to convert.
     */
    public static void bytesFromInt(byte[] array, int offset, int value) {
        array[offset+0] = (byte) ((value>>0) &0xFF);
        array[offset+1] = (byte) ((value>>8) &0xFF);
        array[offset+2] = (byte) ((value>>16)&0xFF);
        array[offset+3] = (byte) ((value>>24)&0xFF);
    }
    
    /**
     * Converts an int into its little-endian byte string representation, and
     * return an array containing it.
     *
     * @param	value	the value to convert.
     * @return	an array containing the byte string.
     */
    public static byte[] bytesFromInt(int value) {
        byte[] array = new byte[4];
        bytesFromInt(array, 0, value);
        return array;
    }
    
    /**
     * Converts an int into a little-endian byte string representation of the
     * specified length.
     *
     * @param	array	the array in which to store the byte string.
     * @param	offset	the offset in the array where the string will start.
     * @param	length	the number of bytes to store (must be 1, 2, or 4).
     * @param	value	the value to convert.
     */
    public static void bytesFromInt(byte[] array, int offset,
                                    int length, int value) {
        assert(length==1 || length==2 || length==4);
        
        switch (length) {
        case 1:
            array[offset] = (byte) value;
            break;
        case 2:
            bytesFromShort(array, offset, (short) value);
            break;
        case 4:
            bytesFromInt(array, offset, value);
            break;
        }
    }


    /**
     * Converts a long into its little-endian byte string representation.
     *
     * @param	array	the array in which to store the byte string.
     * @param	offset	the offset in the array where the string will start.
     * @param	value	the value to convert.
     */
    public static void bytesFromLong(byte[] array, int offset, long value) {
        array[offset+0] = (byte) ((value>>0) &0xFF);
        array[offset+1] = (byte) ((value>>8) &0xFF);
        array[offset+2] = (byte) ((value>>16)&0xFF);
        array[offset+3] = (byte) ((value>>24)&0xFF);
        array[offset+4] = (byte) ((value>>32)&0xFF);
        array[offset+5] = (byte) ((value>>40)&0xFF);
        array[offset+6] = (byte) ((value>>48)&0xFF);
        array[offset+7] = (byte) ((value>>56)&0xFF);
    }


    /**
     * Converts to a short from its little-endian byte string representation.
     *
     * @param	array	the array containing the byte string.
     * @param	offset	the offset of the byte string in the array.
     * @return	the corresponding short value.
     */
    public static short bytesToShort(byte[] array, int offset) {
        return (short) ((((short) array[offset+0] & 0xFF) << 0) |
                        (((short) array[offset+1] & 0xFF) << 8));
    }
    
    /**
     * Converts to an unsigned short from its little-endian byte string
     * representation.
     *
     * @param	array	the array containing the byte string.
     * @param	offset	the offset of the byte string in the array.
     * @return	the corresponding short value.
     */
    public static int bytesToUnsignedShort(byte[] array, int offset) {
        return (((int) bytesToShort(array, offset)) & 0xFFFF);
    }
    
    /**
     * Converts to an int from its little-endian byte string representation.
     *
     * @param	array	the array containing the byte string.
     * @param	offset	the offset of the byte string in the array.
     * @return	the corresponding int value.
     */
    public static int bytesToInt(byte[] array, int offset) {
        return (int) ((((int) array[offset+0] & 0xFF) << 0)  |
                      (((int) array[offset+1] & 0xFF) << 8)  |
                      (((int) array[offset+2] & 0xFF) << 16) |
                      (((int) array[offset+3] & 0xFF) << 24));
    }
    
    /**
     * Converts to an int from a little-endian byte string representation of the
     * specified length.
     *
     * @param	array	the array containing the byte string.
     * @param	offset	the offset of the byte string in the array.
     * @param	length	the length of the byte string.
     * @return	the corresponding value.
     */
    public static int bytesToInt(byte[] array, int offset, int length) {
        assert(length==1 || length==2 || length==4);
        
        switch (length) {
        case 1:
            return array[offset];
        case 2:
            return bytesToShort(array, offset);
        case 4:
            return bytesToInt(array, offset);
        default:
            return -1;
        }
    }

    /**
     * Converts to a string from a possibly null-terminated array of bytes.
     *
     * @param	array	the array containing the byte string.
     * @param	offset	the offset of the byte string in the array.
     * @param	length	the maximum length of the byte string.
     * @return	a string containing the specified bytes, up to and not
     *		    including the null-terminator (if present).
     */
    public static String bytesToString(byte[] array, int offset, int length) {
        int i;
        for (i=0; i<length; i++) {
            if (array[offset+i] == 0)
                break;
        }
        
        return new String(array, offset, i);
    }
    
    /** 
     * Masks out and shifts a bit substring.
     *
     * @param	bits	the bit string.
     * @param	lowest	the first bit of the substring within the string.
     * @param	size	the number of bits in the substring.
     * @return	the substring.
     */
    public static int extract(int bits, int lowest, int size) {
        if (size == 32)
            return (bits >> lowest);
        else
            return ((bits >> lowest) & ((1<<size)-1));
    }
    
    /** 
     * Masks out and shifts a bit substring.
     *
     * @param	bits	the bit string.
     * @param	lowest	the first bit of the substring within the string.
     * @param	size	the number of bits in the substring.
     * @return	the substring.
     */
    public static long extract(long bits, int lowest, int size) {
        if (size == 64)
            return (bits >> lowest);
        else
            return ((bits >> lowest) & ((1L<<size)-1));
    }
    
    /** 
     * Masks out and shifts a bit substring; then sign extend the substring.
     *
     * @param	bits	the bit string.
     * @param	lowest	the first bit of the substring within the string.
     * @param	size	the number of bits in the substring.
     * @return	the substring, sign-extended.
     */
    public static int extend(int bits, int lowest, int size) {
        int extra = 32 - (lowest+size);
        return ((extract(bits, lowest, size) << extra) >> extra);
    }
        
    /** 
     * Tests if a bit is set in a bit string.
     *
     * @param	flag	the flag to test.
     * @param	bits	the bit string.
     * @return	<tt>true</tt> if <tt>(bits & flag)</tt> is non-zero.
     */
    public static boolean test(long flag, long bits) {
        return ((bits & flag) != 0);
    }

    /**
     * Creates a padded upper-case string representation of the integer
     * argument in base 16.
     *
     * @param	i	an integer.
     * @return	a padded upper-case string representation in base 16.
     */
    public static String toHexString(int i) {
        return toHexString(i, 8);
    }
    
    /**
     * Creates a padded upper-case string representation of the integer
     * argument in base 16, padding to at most the specified number of digits.
     *
     * @param	i	an integer.
     * @param	pad	the minimum number of hex digits to pad to.
     * @return	a padded upper-case string representation in base 16.
     */
    public static String toHexString(int i, int pad) {
        String result = Integer.toHexString(i).toUpperCase();
        while (result.length() < pad)
            result = "0" + result;
        return result;
    }

    /**
     * Divides two non-negative integers, round the quotient up to the nearest
     * integer, and return it.
     *
     * @param	a	the numerator.
     * @param	b	the denominator.
     * @return	<tt>ceiling(a / b)</tt>.
     */
    public static int divRoundUp(int a, int b) {
        assert(a >= 0 && b > 0);
        
        return ((a + (b-1)) / b);	
    }

    /**
     * Computes the inner product of two long arraies.
     *
     * @param	v1	one vector
     * @param	v2	another vector
     * @return	inner product of <code>v1</code> and <code>v2</code>
     * @throws  IllegalArgumentException if the dimesionalities of the two 
     *          vectors do not match.
     */
    
    public static long innerProduct(long[] v1, long[] v2) {
        if(v1.length != v2.length) 
            throw new IllegalArgumentException("dimesionalities do not match!");
        long s = 0;        
        for(int i = 0; i < v1.length; i++)
            s += v1[i]*v2[i];
        
        return s;
    }
    
    /**
     * Computes the inner product of one integer array and one long array.
     *
     * @param	v1	the integer vector
     * @param	v2	the long vector
     * @return	inner product of <code>v1</code> and <code>v2</code>
     * @throws  RuntimeException if the dimesionalities of the two vectors do 
     *          not match.
     */

    public static long innerProduct(int[] v1, long[] v2) {
        if(v1.length != v2.length) 
            throw new RuntimeException("dimesionalities do not match!");
        long s = 0;        
        for(int i = 0; i < v1.length; i++)
            s += v1[i]*v2[i];
        
        return s;
    }


    /**
     * Computes the inner product of two doulbe arraies
     *
     * @param	v1	one double vector
     * @param	v2	the other double vector
     * @return	inner product of <code>v1</code> and <code>v2</code>
     * @throws  RuntimeException if the dimesionalities of the two vectors do 
     *          not match.
     */
    public static double innerProduct(double[] v1, double[] v2) {
        if(v1.length != v2.length) 
            throw new RuntimeException("dimesionalities do not match!");
        double s = 0;
        for(int i = 0; i < v1.length; i++)
            s += v1[i]*v2[i];
        
        return s;
    }


    /**
     * A java and simplified version of daxpy, constant times a vector plus a 
     * vector. Unlike its BLAS counterpart, it does NOT use unrolled loop. This 
     * function is for verifying the computation. NO optimization is done.
     * 
     *
     * This function does
     *
     *     y = a*x + y
     *
     * where a is a scaler and x, y are vectors. 
     *
     */
    public static void laxpy(long a, long[] x, long[] y) {
        for(int i = 0; i < x.length; i++) {
            y[i] = a*x[i]+y[i];
        }
    }

    public static void laxpy(double a, double[] x, double[] y) {
        for(int i = 0; i < x.length; i++) {
            y[i] = a*x[i]+y[i];
        }
    }


    /**
     * Returns a number whose value is between [-m/2, m/2) and differs 
     * from data by a multiple of m.
     *
     * @param	data_long_integer_mod	a long integer.
     * @param   modulus       the modulus.
     * @return	a number between [-m/2, m/2) that differs from data by a multiple of m.
     */
    public static long mod(long data_long_integer_mod, long modulus) {
        long mod_result_long = data_long_integer_mod % modulus;
        if(mod_result_long < 0){
            mod_result_long += modulus;
        }


        double upperBound = Math.floor((double)modulus/2.);
        if(mod_result_long >= Math.floor((double)modulus/2.)){
            mod_result_long -= modulus;
        }

        return mod_result_long;
    }


    /**
     * Converts the integers in the given array <code>data</code> into double 
     * precision floating point numbers. The integers should be between 
     *
     *     [-floor(F/2), floor(F/2)] if F is odd
     *     [-floor(F/2), floor(F/2)-1] if F is even
     * 
     * and the real numbers will be between [-R, R].
     * <p>
     * This provides a mapping between the finite field [-F/2, F/2] where our 
     * P4P computations are performed and the field of real numbers where many 
     * applications run.
     *
     * @param	data	the array of longs to be converted
     * @param   offset  starting position in the array
     * @param   len     then number of elements to be cpnverted.
     * @param   F       the size of the finite field where private P4P 
     *                  computation is carried out
     * @param   R       the maximum value of the floating point number that 
     *                  the system supports.
     * @return	an array of doubles between [-R, R].
     */
    public static double[] itor(long[] data, int offset, int len, long F, 
                                double R) {
        double [] v = new double[len];
        
        double alpha = 2.d*R/F;
        for(int i = 0; i < len; i++)
            v[i] = (double)data[offset+i]*alpha;
        
        return v;
    }


    /**
     * Converts the integers in the given array <code>data</code> into double 
     * precision floating point numbers. The integers should be between 
     *
     *     [-floor(F/2), floor(F/2)] if F is odd
     *     [-floor(F/2), floor(F/2)-1] if F is even
     * 
     * and the real numbers will be between [-R, R].
     * <p>
     * This provides a mapping between the finite field [-F/2, F/2] where our 
     * P4P computations are performed and the field of real numbers where many 
     * applications run.
     *
     * @param	data	the array of longs to be converted
     * @param   F       the size of the finite field where private P4P 
     *                  computation is carried out
     * @param   R       the maximum value of the floating point number that 
     *                  the system supports.
     * @return	an array of doubles between [-R, R].
     */
    public static double[] itor(long[] data, long F, double R) {
        return itor(data, 0, data.length, F, R);
        /*
          double [] v = new double[data.length];
          
          double alpha = 2.d*R/F;
          for(int i = 0; i < data.length; i++)
          v[i] = (double)data[i]*alpha;
          
          return v;
        */
    }


    /**
     * Converts the integers in the given array <code>data</code> into double 
     * precision floating point numbers. The integers should be between 
     *
     *     [-floor(F/2), floor(F/2)] if F is odd
     *     [-floor(F/2), floor(F/2)-1] if F is even
     * 
     * and the real numbers will be between [-R, R].
     * <p>
     * This provides a mapping between the finite field [-F/2, F/2] where our 
     * P4P computations are performed and the field of real numbers where many 
     * applications run.
     *
     * @param	data	the array of longs to be converted
     * @param   F       the size of the finite field where private P4P 
     *                  computation is carried out
     * @param   R       the maximum value of the floating point number that 
     *                  the system supports.
     * @return	an array of doubles between [-R, R].
     */
    public static double[][] itor(long[][] data, long F, double R) {
        double [][] v = new double[data.length][data[0].length];
        
        for(int i = 0; i < data.length; i++)
            v[i] = Util.itor(data[i], F, R);
        
        return v;
    }


    /**
     * Converts the double precision floating point numbers in the given array 
     * <code>data</code> into integers field. The integers should be between 
     *
     *     [-floor(F/2), floor(F/2)] if F is odd
     *     [-floor(F/2), floor(F/2)-1] if F is even
     * 
     * and the real numbers will be between [-R, R].
     * <p>
     * This provides a mapping between the finite field [-F/2, F/2] where our
     * P4P computations are performed and the field of real numbers where many
     * applications run.
     *
     * @param	data	the array of doubles to be converted
     * @param   offset  starting position in the array
     * @param   len     then number of elements to be cpnverted.
     * @param   F       the size of the finite field where private P4P 
     *                  computation is carried out
     * @param   R       the maximum value of the floating point number that 
     *                  the system supports.
     * @return	an array of integers between [-F/2, F/2).
     */
    public static long[] rtoi(double[] data, int offset, int len, long F, 
                              double R) {
        long [] v = new long[len];
        
        double alpha = 2.d*R/F;
        for(int i = 0; i < len; i++)
            v[i] = Math.round(data[i+offset]/alpha);
        
        return v;
    }

    /**
     * Converts the double precision floating point numbers in the given array 
     * <code>data</code> into integers field. The integers should be between 
     *
     *     [-floor(F/2), floor(F/2)] if F is odd
     *     [-floor(F/2), floor(F/2)-1] if F is even
     * 
     * and the real numbers will be between [-R, R].
     * <p>
     * This provides a mapping between the finite field [-F/2, F/2] where our 
     * P4P computations are performed and the field of real numbers where many
     * applications run.
     *
     * @param	data	the array of doubles to be converted
     * @param   F       the size of the finite field where private P4P 
     *                  computation is carried out
     * @param   R       the maximum value of the floating point number that 
     *                  the system supports.
     * @return	an array of integers between [-F/2, F/2).
     */
    public static long[] rtoi(double[] data, long F, double R) {
        return rtoi(data, 0, data.length, F, R);
        /*
          long [] v = new long[data.length];
          
          double alpha = 2.d*R/F;
          for(int i = 0; i < data.length; i++)
          v[i] = Math.round(data[i]/alpha);
          
          return v;
        */
    }

    /**
     * Converts the double precision floating point numbers in the given array 
     * <code>data</code> into integers field. The integers should be between 
     *
     *     [-floor(F/2), floor(F/2)] if F is odd
     *     [-floor(F/2), floor(F/2)-1] if F is even
     * 
     * and the real numbers will be between [-R, R].
     * <p>
     * This provides a mapping between the finite field [-F/2, F/2] where our
     * P4P computations are performed and the field of real numbers where many
     * applications run.
     *
     * @param	data	the array of doubles to be converted
     * @param   F       the size of the finite field where private P4P 
     *                  computation is carried out
     * @param   R       the maximum value of the floating point number that 
     *                  the system supports.
     * @return	an array of integers of length <code>len</code> between [-F/2, F/2).
     */
    public static long[][] rtoi(double[][] data, long F, double R) {
        long [][] v = new long[data.length][data[0].length];
        
        for(int i = 0; i < data.length; i++)
            v[i] = Util.rtoi(data[i], F, R);
        
        return v;
    }
    
    /**
     * Returns the minimum value in the given double array.
     *
     * @param	data	the array of doubles 
     * @return	the minimum value in <code>data</code>
     */
    public static double min(double[] data) {
        double min = Double.MAX_VALUE; 
        for(int i = 0; i < data.length; i++)
            min = min > data[i] ? data[i] : min;
        return min;
    }
    
    /**
     * Returns the maximum value in the given double array.
     *
     * @param	data	the array of doubles 
     * @return	the maximum value in <code>data</code>
     */
    public static double max(double[] data) {
        double max = Double.MIN_VALUE; 
        for(int i = 0; i < data.length; i++)
            max = max < data[i] ? data[i] : max;
        return max;
    }

    /**
     * Returns the maximum value in the given double array.
     *
     * @param	data	the array of doubles 
     * @return	the maximum value in <code>data</code>
     */
    public static double max(double[][] data) {
        double max = Double.MIN_VALUE; 
        for(int i = 0; i < data.length; i++) {
            double mx = Util.max(data[i]);
            max = max < mx ? mx : max;
        }
        return max;
    }
    

    /**
     * Returns the maximum absolute value in the given double array.
     *
     * @param	data_array_double	the array of doubles
     * @return	the maximum absolute value in <code>data</code>
     */
    public static double maxAbs(double[] data_array_double) {
        return maxAbs(data_array_double, 0, data_array_double.length);
        /*
          double max = 0.; 
          for(int i = 0; i < data.length; i++) {
          double mx = Math.abs(data[i]);
          max = max < mx ? mx : max;
          }
          return max;
        */
    }


    /**
     * Returns the maximum absolute value in the given long array.
     *
     * @param	data	the array of longs 
     * @return	the maximum absolute value in <code>data</code>
     */
    public static long maxAbs(long[] data) {
        //	return maxAbs(data, 0, data.length);
        
        long max = 0; 
        for(int i = 0; i < data.length; i++) {
            long mx = (long)Math.abs(data[i]);
            max = max < mx ? mx : max;
        }
        return max;
        
    }
    

    /**
     * Returns the maximum absolute value in the given long array.
     *
     * @param	data	the array of longs 
     * @return	the maximum absolute value in <code>data</code>
     */
    public static long maxAbs(long[] data, int offset, int len) {
        long max = 0; 
        for(int i = 0; i < len; i++) {
            long mx = (long)Math.abs(data[offset+i]);
            max = max < mx ? mx : max;
        }
        return max;
    }
    

    public static double maxAbs(double[] data, int offset, int len) {
        double max = 0.; 
        for(int i = 0; i < len; i++) {
            double mx = Math.abs(data[offset+i]);
            max = max < mx ? mx : max;
        }
        return max;
    }
    
    /**
     * Returns the maximum absolute value in the given double array.
     *
     * @param	data_array_double	the array of doubles
     * @return	the maximum absolute value in <code>data</code>
     */
    public static double maxAbs(double[][] data_array_double) {
        double max = 0.; 
        for(int i = 0; i < data_array_double.length; i++) {
            double mx = Util.maxAbs(data_array_double[i]);
            max = max < mx ? mx : max;
        }
        return max;
    }
    

    /**
     * Returns the maximum value in the given long array.
     *
     * @param	data_arrays_long	the array of longs
     * @return	the maximum value in <code>data</code>
     */
    public static long max(long[] data_arrays_long) {
        long max = Long.MIN_VALUE; 
        for(int i = 0; i < data_arrays_long.length; i++)
            max = max < data_arrays_long[i] ? data_arrays_long[i] : max;
        return max;
    }

    /**
     * Generates a random vector in Z_F with approximately the given L2-norm.
     * The algorithm is as follows: first a random m-dimensional vector over
     * Z_F is generated by selecting each elements randomly from Z_F. The 
     * vector is then scaled to the desired length, rounding each element to 
     * the nearest long. Note that Z_F is defined as 
     *
     *     [-floor(F/2), floor(F/2)] if F is odd
     *     [-floor(F/2), floor(F/2)-1] if F is even 
     *
     *   
     * NOTE:   
     *         F is to big. A random vector generated this way is so big 
     *         that the scaling factor is essentially 0, resulting in a zero
     *         vector. Instead, we restrict each element between [-L, L]. We 
     *         are choosing from a set with (2L)^m elements, instead of F^m,
     *         where L is chosen to be 1000. This function is only for test. 
     *         Should be OK. 
     * @param dimension    the dimensionality of the vector
     * @param ZF_orderGroup_utilRandV    the order of the group Z_F
     * @param l2_norm_549OR219_Util_randVector   the desired l2-norm of the vector. If it is 0, then a random
     *             vector in (Z_F)^m is generated.
     * @return	   a random vector over Z_F L2-norm equal <code>l2</code>
     */
// order of Z_F
    public static long[] randVector(int dimension, long ZF_orderGroup_utilRandV, double l2_norm_549OR219_Util_randVector) {
        long[] data_Util_randVector = new long[dimension];

        BigInteger bigF_randV = null;
        if(l2_norm_549OR219_Util_randVector <=0){
            bigF_randV = new BigInteger(Long.toString(ZF_orderGroup_utilRandV));
        }
        double myL2_SQUARE_util = 0.;
        int L_10000_util = 10000;
        int[] l2_positive_counter_for_10_dimension = new int[2];
        for(int dimension_id = 0; dimension_id < dimension; dimension_id++) {
            if(l2_norm_549OR219_Util_randVector > 0) {
                data_Util_randVector[dimension_id] = rand.nextInt(2*L_10000_util+1)-L_10000_util;
                myL2_SQUARE_util += (double)((double)data_Util_randVector[dimension_id]*(double)data_Util_randVector[dimension_id]);
                l2_positive_counter_for_10_dimension[0]++;
            }
            else {
                data_Util_randVector[dimension_id] = randomBigInteger(bigF_randV).longValue();
                // A random long in [0, F-1]
                data_Util_randVector[dimension_id] -= Math.floor((double) ZF_orderGroup_utilRandV / 2.);
                // Shift to Z_F
                l2_positive_counter_for_10_dimension[1]++;
            }
        }
        System.out.println("l2_positive_counter_for_10_dimension: " + Arrays.toString(l2_positive_counter_for_10_dimension));
        System.out.println("data_Util_randVector: "+ Arrays.toString(data_Util_randVector));

        if(l2_norm_549OR219_Util_randVector > 0) {
            double myL2_SQRT = Math.sqrt(myL2_SQUARE_util);
            double scale_Util_randV = l2_norm_549OR219_Util_randVector/myL2_SQRT;
            for(int did = 0; did < dimension; did++) {
                long data_half_AM_scale = 0;
                long data_ADD_half = (long)(((double)data_Util_randVector[did]+0.5)*scale_Util_randV);
                long data_MINUS_half = (long)(((double)data_Util_randVector[did]-0.5)*scale_Util_randV);
                if(data_Util_randVector[did] > 0) {
                    data_half_AM_scale = data_ADD_half;
                    data_Util_randVector[did] = data_half_AM_scale;
                }
                else{
                    data_half_AM_scale  = data_MINUS_half;
                    data_Util_randVector[did] = data_half_AM_scale;
                }
                // Round to the closest long
            }
        }
        return data_Util_randVector;
    }


    /**
     * Adds two vectors in the field Z_F.
     * @param v1   one vector
     * @param v2   the other vector
     * @param vector_sum    the vector where the resulting <code>v1+v2</code> should
     *             be stored.
     * @param group_order_F_Util    the order of the group Z_F
     * @throws     IllegalArgumentException if the dimesionalities of the 
     *             vectors do not match.
     */
    public static void vectorAdd(long[] v1, long[] v2, long[] vector_sum, long group_order_F_Util) {
        int vector_dimension = vector_sum.length; // dimensionality of vector
        if(v1.length != vector_dimension || v2.length != vector_dimension)
            throw new IllegalArgumentException("dimesionalities do not match!");

        for(int dimension_id = 0; dimension_id < vector_dimension; dimension_id++) {
            // Assuming F is at least a few bits less than a long, a single 
            // addition won't cause overflow. So we can do mod afterwards.
            // But we do need to do mod once for a few additions since the 
            // shares can be any number in Z_F. 
            vector_sum[dimension_id] = mod(v1[dimension_id] + v2[dimension_id], group_order_F_Util);
        }
    }
}
