/**
 * Copyright (c) 2007 Regents of the University of California.
 * All rights reserved.
 * <p>
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * <p>
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * <p>
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * <p>
 * 3. The name of the University may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 * <p>
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

package p4p.user;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;


import net.i2p.util.NativeBigInteger;

import p4p.util.Util;
import p4p.util.StopWatch;
import p4p.util.P4PParameters;
import p4p.crypto.Proof;
import p4p.crypto.BitVectorCommitment;

/**
 * Changes:
 * <p>
 * 10/12/2007: The method implemented in this class is OUT OF DATE. Do NOT
 * use this class.
 * 12/05/2005: Moved to user package.
 */

/**
 *
 * A UserVector class. It contains the user data (an m-dimensional vector over
 * a small finite field Z_F where F is a (small) prime. The class encapsulates
 * some operations as well as a ZKP that proves the L2 norm of the user vector
 * is bounded by L.
 *
 * NOTE: The L2-norm bound ZKP implemented in this class is OUT OF DATE. It 
 * should be replaced by the protocol implemented in <code>UserVector2</code>
 * which is more efficient and secure. This class is kept here for reference
 * purposes only. It is not being maintained and hasn't been throughoutly 
 * tested. Use <code>UserVector2</code> instead.
 *
 * @author ET 10/11/2005
 */

public class UserVector extends P4PParameters {
    protected long[] data_UV = null;   // The user data
    protected int dimension = -1;          // The dimension of user vector

    protected long F_UV = -1;
    // The order of the (small) finite field over which all the 
    // computations are carried out. It should be a prime of 
    // appropriate length (e.g. the length of a long).

    protected int[][] checkCoVector = null;    // The checksum coefficient vectors.

    protected long L_UV = -1;
    protected int l_UV;

    /**
     */
    public UserVector(long[] data_UV_P, long F_UV_P, int log_2_m_UV_P) {
        if (F_UV_P < 0 || !new BigInteger(new Long(F_UV_P).toString()).isProbablePrime(200))
            throw new RuntimeException("Field order must be positive prime.");

        this.data_UV = data_UV_P;
        this.dimension = data_UV_P.length
        ;
        this.F_UV = F_UV_P;
        this.l_UV = log_2_m_UV_P;
        this.L_UV = ((long) 1) << l_UV - 1;

        long singaporeModF;
        // Convert the numbers into the finite field:
        if (data_UV_P != null) {
            for (int i_dim_UV = 0; i_dim_UV < dimension; i_dim_UV++) {
                 singaporeModF = Util.mod(data_UV_P[i_dim_UV], F_UV_P);
                 this.data_UV[i_dim_UV] = singaporeModF;
                 System.out.println("i_dim_UV: " + i_dim_UV + " singaporeModF: "+ singaporeModF);
            }
            // The range should be [-F/2, F/2)
        }
    }


    public UserVector(int m, long FieldSize_larger_than_bitLength_UV1_P, int log_2_m_UV_P) {
        if (FieldSize_larger_than_bitLength_UV1_P < 0 || !new BigInteger(new Long(FieldSize_larger_than_bitLength_UV1_P).toString()).isProbablePrime(200))
            throw new RuntimeException("Field order must be positive prime.");

        this.dimension = m;
        this.F_UV = FieldSize_larger_than_bitLength_UV1_P;
        this.l_UV = log_2_m_UV_P;
        this.L_UV = ((long) 1) << log_2_m_UV_P - 1;
    }

    /**
     * Set the checksum coefficient vectors (the ck's). This is to prepare for the
     * L2 norm bound ZKP.
     *
     * @param    server_getChallengeVectors_sim    the checksum coefficient vectors
     */
    public void setChecksumCoefficientVectors(int[][] server_getChallengeVectors_sim) {
        for (int i = 0; i < server_getChallengeVectors_sim.length; i++) {
            // every challenge subarray must equal to dimension
            if (server_getChallengeVectors_sim[i].length != dimension) {
                throw new RuntimeException("Incorrect dimension for c[" + i + "]!");
            }
// 	    for(int j = 0; j < m; j++) {
// 		if(c[i][j] != 1 && c[i][j] != -1)
// 		    throw new RuntimeException("Incorrect checksum coefficient: c["
// 					       + i + "][" + j + "] = " + c[i][j]);
// 	    }
        }

        this.checkCoVector = server_getChallengeVectors_sim;
    }


    /**
     */
    public long[] getUserData() {
        return data_UV;
    }

    /**
     * A zero-knowledge proof that the vector L2 norm is bounded by L.
     *
     * A proof essentially consists of l bit vector commitment, and their proofs,
     * and one vector commitment to the checksum vector (consisting of the checksums
     * that the user claimed to be small), where l is the max number of bits each 
     * valid checksum can have (i.e. L = 2^{l-1}). The  l bit vector commitments and
     * one vector commitment are stored in the proof's commitment field while the
     * corresponding proofs are stored in a separate array. 
     *
     */
    public class L2NormBoundProof extends Proof {
        private BitVectorCommitment.BitVectorCommitmentProof[] bitVecProofs = null;
        private int[] passed = null;   // The indexes of the checksums that are bounded
        private long[] checksums = null;


        // 1. Checksum
        // 2. BitVectorCommitmentProof

        // Construct the ZKP that the commitment contains a bit
        public void construct() {
            if (checkCoVector == null)
                throw new RuntimeException("Checksum vector not set yet.");

            Vector<Integer> oked = new Vector<Integer>();
            Vector<Long> cs = new Vector<Long>();    // Those checksums that are < L


            // Compute the checksums:
            for (int i = 0; i < checkCoVector.length; i++) {
                long s_checksums_long_UV = 0;
                for (int j = 0; j < dimension; j++) {
                    //s += c[i][j]*data[j];
                    if (checkCoVector[i][j] == 1)
                        s_checksums_long_UV += data_UV[j];
                    else
                        s_checksums_long_UV -= data_UV[j];
                    // Maybe it is faster this way?
                    /**
                     * Note that although all the normal compuations are done in
                     * a small finite field, we don't restrict the size of the
                     * checksum here (i.e. no mod operation). We allow s_checksums_long_UV to grow
                     * to check the L2 norm of the user vector.
                     */
                }

                if (s_checksums_long_UV < 0) s_checksums_long_UV = Math.abs(s_checksums_long_UV);
                //DEBUG("checksums[" + i + "] = " + s);
                if (s_checksums_long_UV < L_UV) {
                    oked.add(new Integer(i));
                    cs.add(new Long(s_checksums_long_UV));
                }
            }

            checksums = new long[cs.size()];
            passed = new int[cs.size()];

            int numBits = 0;
            for (int i = 0; i < checksums.length; i++) {
                passed[i] = ((Integer) oked.elementAt(i)).intValue();
                checksums[i] = ((Long) cs.elementAt(i)).longValue();
                numBits = Math.max(numBits, Long.toBinaryString(checksums[i]).length());
                //DEBUG("checksums[" + i + "] = " + checksums[i]);
            }

            DEBUG("Largest checksum has " + numBits + " bits.");

            if (checksums.length == 0) return;
            // All checksums are greater than L. We fail


            // Commit to the bit vectors:
            BitVectorCommitment bvc = new BitVectorCommitment(P4PParameters.getGenerators(checksums.length),
                    P4PParameters.getGenerator());
            BigInteger sRandomness = BigInteger.ZERO;
// 	    byte[][] bits = new byte[checksums.length][];	
// 	    for(int i = 0; i < checksums.length; i++) {
// 		bits[i] = new byte[8];
// 		Util.bytesFromLong(bits[i], 0, checksums[i]);
// 	    }

            bitVecProofs = new BitVectorCommitment.BitVectorCommitmentProof[l_UV];
            commitment = new BigInteger[l_UV + 2];
            commitment[l_UV] = BigInteger.ONE;
            // The commitment to the vector. To be calculated by multiplying all the bit vector commitments

            for (int i = 0; i < l_UV; i++) {
                commitment[i] = bvc.commit(checksums, i);


                NativeBigInteger c = new NativeBigInteger(commitment[i]);
                // Turn it into a NativeBigInteger because we need to do pow.
                BigInteger e = new BigInteger(new Long(((long) 1) << i).toString());
                // 2^j
                commitment[l_UV] = commitment[l_UV].multiply(c.modPow(e, p)).mod(p);

                BigInteger r = bvc.getRandomness();
                sRandomness = sRandomness.add(r.multiply(new BigInteger(new Long(((long) 1) << i).toString())));
                // += r[i]*2^i

                // We also need to append the bit vector commitment proofs:
                bitVecProofs[i] = (BitVectorCommitment.BitVectorCommitmentProof) bvc.getProof();
            }

            // Now commit to the vector s
// 	    VectorCommitment vc = new VectorCommitment(P4PParameters.getGenerators(checksums.length), 
// 						       P4PParameters.getGenerator()) ;
// 	    commitment[l] = vc.commit(checksums, sRandomness);

            // We don't need to compute the commitment separately, which takes some exponentiations.
            // Just multiply all the bit vector commitments!


            // And store the randomness here:
            commitment[l_UV + 1] = sRandomness;
        }

        public BitVectorCommitment.BitVectorCommitmentProof[] getBitVectorProofs() {
            return bitVecProofs;
        }

        public int[] getPassed() {
            return passed;
        }

        public long[] getChecksums() {
            return checksums;
        }
    }

    public Proof getL2NormBoundProof() {
        L2NormBoundProof proof = new L2NormBoundProof();
        proof.construct();
        return proof;
    }


    // The verifier:

    // The ZKP verify
    public boolean verify(Proof proof, int zkpThresold) {
        L2NormBoundProof l2Proof = (L2NormBoundProof) proof;
        BitVectorCommitment.BitVectorCommitmentProof[] bvcProofs = l2Proof.getBitVectorProofs();
        long[] s = l2Proof.getChecksums();
        int[] passed = l2Proof.getPassed();
        BigInteger[] commitment = l2Proof.getCommitment();

        if (passed.length < zkpThresold) {
            DEBUG("Too few checksums that are smaller than L.");
            return false;
        }

        // Pretend we can see the user vector and the checksum. In a real deployment, they
        // will only be half of them
        for (int i = 0; i < s.length; i++) {
            // First make sure the checksums are computed correctly:
            if (s[i] != Math.abs(Util.innerProduct(checkCoVector[passed[i]], data_UV))) {
                DEBUG("Checksum " + i + " not computed correctly!");
                return false;
            }
        }

        // Next check that the commitments agree:
        BigInteger z = BigInteger.ONE;
        for (int i = 0; i < l_UV; i++) {
            NativeBigInteger c = new NativeBigInteger(commitment[i]);
            // Turn it into a NativeBigInteger because we need to do pow.
            BigInteger e = new BigInteger(new Long(((long) 1) << i).toString());
            // 2^j
            z = z.multiply(c.modPow(e, p)).mod(p);
        }

        // There are l+2 BigIntegers in commitment, commitment[l] and commitment[l+1]
        // are the commitment to the vector of checksums that the user claims to be
        // small and the randomness used, respectively.

// 	VectorCommitment vc = new  VectorCommitment(P4PParameters.getGenerators(s.length), 
// 						    P4PParameters.getGenerator()) ;	
// 	if(!z.equals(vc.commit(s, commitment[l+1])) || !z.equals(commitment[l])) {

        /**
         * We don't really need to compute the vector commitment, which takes some
         * exponentiations. In a real application, the vector commitment will be given
         * to us by the prover. We don't open it now. We only verify that it contains
         * a vector of certain bits. We then use this commitment to verify the
         * computation, in an active adversary setting.
         */

        if (!z.equals(commitment[l_UV])) {
            DEBUG("Checksum vector commitments don't agree!");
            DEBUG("z = " + z);
            DEBUG("commitment[l] = " + commitment[l_UV]);
            return false;
        }

        // Now verify the bit vector commitments:
        BitVectorCommitment bvc = new BitVectorCommitment(P4PParameters.getGenerators(s.length),
                P4PParameters.getGenerator());

        for (int i = 0; i < l_UV; i++) {
            if (!bvc.verify(bvcProofs[i])) {
                DEBUG("Bit vector commitment No." + i + " failed");
                return false;
            }
        }

        return true;
    }


    /**
     * Test the UserVector L2 norm bound ZKP.
     *
     *  ./bin/p4p p4p.BitVectorCommitment -k 1024 -m 1000000
     *
     * Total time: xxx2046921 ms. Average: xxx3411.535 ms per loop
     *
     * This is with l = 32, N = 100, T = 31.
     *
     * Note that the zkp is probabilistic and its sucess probability is
     * only accurate when m is large, So with small m it may not pass 
     * some of the tests.
     *
     */
    public static void main(String[] args) {
        //throws IOException {
        int k = 512;
        int m = 10;
        int nLoops = 10;
        boolean doBench = false;
        boolean worstcase = false;
        // test the worst case cost. i.e. every vector should pass. this is when the verifier spends longest time.

        for (int i = 0; i < args.length; ) {
            String arg = args[i++];
            if (arg.length() > 0 && arg.charAt(0) == '-') {
                if (arg.equals("-k")) {
                    try {
                        k = Integer.parseInt(args[i++]);
                    } catch (NumberFormatException e) {
                        k = 512;
                    }
                } else if (arg.equals("-m")) {
                    try {
                        m = Integer.parseInt(args[i++]);
                    } catch (NumberFormatException e) {
                        m = 10;
                    }
                } else if (arg.equals("-l")) {
                    try {
                        nLoops = Integer.parseInt(args[i++]);
                    } catch (NumberFormatException e) {
                        nLoops = 10;
                    }
                } else if (arg.equals("-d")) {
                    debug = true;
                } else if (arg.equals("-w")) {
                    worstcase = true;  // test the worst case cost. i.e. every vector should pass. this is when the verifier spends longest time.
                } else if (arg.equals("-bench")) {
                    doBench = true;
                }
            }
        }

        System.out.println("k = " + k);
        System.out.println("m = " + m);
        System.out.println("nLoops = " + nLoops);

        // Setup the parameters:
        P4PParameters.initialize(k, false);
        SecureRandom rand = null;
        try {
            rand = SecureRandom.getInstance("SHA1PRNG");
        } catch (java.security.NoSuchAlgorithmException e) {
            System.err.println("NoSuchAlgorithmException!");
            e.printStackTrace();
            rand = new SecureRandom();
        }

        rand.nextBoolean();

        // Now generate some data to be used:
        //	int l = 32;    // We restrict L to be 32 bits

        // Lets make l = log_2 (m)
        int log_2_m = Math.max(10, (int) Math.ceil(Math.log(m) / Math.log(2.)));


        // We restrict L to be 32 bits
        long L_to_32_bits = ((long) 2) << log_2_m - 1;
        long F = BigInteger.probablePrime(log_2_m + 10, rand).longValue();
        // Make the field size to be 10 bits larger than l

        // Definie the number of iterations that the bound ZKP must have:
        int zkpIterations = 50;
        //int zkpThreshold = (int)((1.-.3173)*(double)zkpIterations);
        // The minimum number of checksums that must be small for
        // us to accept the vector as valid.

        int zkpThreshold = (int) (.3173 * (double) zkpIterations);
        // TODO: Check what this number is


        System.out.println("log_2_m = " + log_2_m + ", L_to_32_bits = " + L_to_32_bits);
        System.out.println("F = " + F);
        System.out.println("zkpIterations = " + zkpIterations + ", zkpThreshold = " + zkpThreshold);

        // Generate the data and the checksum coefficient vector:
        long[] data = new long[m];
        int[][] c = new int[zkpIterations][];

        if (doBench) {
            System.out.println("Benchmarking UserVector L2 bound ZKP for " + nLoops + " loops .");
        } else {
            System.out.println("Testing UserVector L2 bound ZKP for " + nLoops + " loops .");
            long start = System.currentTimeMillis();
            for (int i = 0; i < nLoops; i++) {
                for (int j = 0; j < m; j++) {
                    data[j] = (long) Math.abs(rand.nextInt());  // Make it small deliberately
                    //DEBUG("d["+j+"] = " + data[j]);
                }

                for (int j = 0; j < zkpIterations; j++) {
                    c[j] = new int[m];
                    for (int kk = 0; kk < m; kk++) {
                        c[j][kk] = rand.nextBoolean() ? 1 : -1;
                        //DEBUG("c["+j+"]["+kk+"] = " + c[j][kk]);
                    }
                }

                UserVector uv = new UserVector(data, F, log_2_m);
                data = uv.getUserData();

                double l2_data_square = 0.;
                for (int j = 0; j < m; j++) {
                    //DEBUG("d["+j+"] = " + data[j]);
                    l2_data_square += (double) data[j] * data[j];
                }

                double l2_data_square_sqrt = Math.sqrt(l2_data_square);
                System.out.println("L2 norm of user data = " + l2_data_square_sqrt);

                uv.setChecksumCoefficientVectors(c);
                L2NormBoundProof proof = (L2NormBoundProof) uv.getL2NormBoundProof();

                boolean shouldPass = l2_data_square_sqrt < L_to_32_bits;
                boolean didPass = uv.verify(proof, zkpThreshold);

                System.out.println("shouldPass = " + shouldPass + ", result = " + didPass);

            }

            long end = System.currentTimeMillis();
            System.out.println("Total time: " + (end - start) + " ms. Average: "
                    + (double) (end - start) / (double) nLoops + " ms per loop");
        }
    }
}

