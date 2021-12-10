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

package p4p.sim;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;

import net.i2p.util.NativeBigInteger;
import java.util.Arrays;
import p4p.util.Util;
import p4p.util.StopWatch;
import p4p.util.P4PParameters;
//import p4p.crypto.SquareCommitment;
//import p4p.crypto.Proof;
//import p4p.crypto.BitCommitment;
//import p4p.crypto.Commitment;
import p4p.user.UserVector2;
import p4p.server.P4PServer;

/**
 * 
 * Providing a simulation framework for a P4P system. This allows one to debug
 * and benchmark the cryptographic primitives without having to provide other
 * components necessary for a real deployment (e.g. secure communication).
 *
 * @author ET 12/10/2005
 */

public class P4PSim extends P4PParameters {
    private static NativeBigInteger g = null;
    private static NativeBigInteger h = null;
    
    private static int security_parameter_Sim = 512;     // Security parameter
    private static int dimension = 10;      // User vector dimension
//    private static int n = 10;      // Number of users
    private static int user_num = 10;      // Number of users
    private static int bitLength = 40;      // Bit length of L
    
    /**
     * Start a simulation.
     */
    public static void main(String[] args) {
        int nLoops = 1;
        boolean doBench = false;
        boolean worstcase = false;
        /**
         * Test the worst case cost. i.e. every vector should pass. This is 
         * when the verifier spends longest time.
         */

        // Definie the number of iterations that the bound ZKP must have:
        int zkpIterations = 1;

        System.out.println("args.length: " + args.length);


        int[] shouldPass_Counter = new int[2];
        shouldPass_Counter[0] = 0;
        shouldPass_Counter[1] = 1;
        for (int i = 0; i < args.length; ) {
            String arg = args[i++];
            if(arg.length() > 0 && arg.charAt(0) == '-') {
                if (arg.equals("-security_parameter_Sim")) {
                    try {
                        security_parameter_Sim = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        security_parameter_Sim = 512;
                    }
                }
                else if(arg.equals("-m")) {
                    try {
                        dimension = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        dimension = 10;
                    }
                }
                else if(arg.equals("-n")) {
                    try {
                        user_num = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        user_num = 10;
                    }
                }
                else if(arg.equals("-N")) {
                    try {
                        zkpIterations = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        zkpIterations = 50;
                    }
                }

                else if(arg.equals("-o")) {
                    try {
                        nLoops = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        nLoops = 10;
                    }
                }

                else if(arg.equals("-l")) {
                    try {
                        bitLength = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        bitLength = 40;
                    }
                }

                else if(arg.equals("-d")) {
                    debug = true;
                }
                else if(arg.equals("-w")) {
                    worstcase = true;
                }
                else if(arg.equals("-bench")) {
                    doBench = true;
                }
            }
        }

        System.out.println("securityParameter = " + security_parameter_Sim);
        System.out.println("dimension = " + dimension);
        System.out.println("n = " + user_num);
        System.out.println("nLoops = " + nLoops);

        // Setup the parameters:
        P4PParameters.initialize(security_parameter_Sim, false);
        SecureRandom rand = null;
        try {
            rand = SecureRandom.getInstance("SHA1PRNG");
        }
        catch(java.security.NoSuchAlgorithmException e) {
            System.err.println("NoSuchAlgorithmException!");
            e.printStackTrace();
            rand = new SecureRandom();
        }
        rand.nextBoolean();

        long L_1099511627776 = ((long)2)<<bitLength - 1; //1099511627776
        long FieldSize_larger_than_bitLength_Sim = BigInteger.probablePrime(Math.min(bitLength+30,62), rand).longValue();
        // Make the field size to be 10 bits larger than l

        // Or just make FieldSize_larger_than_bitLength_Sim 62 bits? Note that we can't use 64 bit since there is no
        // unsigned long in java.
        //FieldSize_larger_than_bitLength_Sim = BigInteger.probablePrime(62, rand).longValue();

        int iteration_N = zkpIterations;
        System.out.println("bitLength = " + bitLength + ", L_1099511627776 = " + L_1099511627776);
        System.out.println("FieldSize_larger_than_bitLength_Sim = " + FieldSize_larger_than_bitLength_Sim);
        System.out.println("zkpIterations = " + zkpIterations);

        // Generate the data and the checksum coefficient vector:
        long[] data_long_1arr = new long[dimension];
        int[][] idle_coefficient_vector = new int[zkpIterations][];
        NativeBigInteger[] two_generators_for_g_h = P4PParameters.getGenerators(2);
        g = two_generators_for_g_h[0];
        h = two_generators_for_g_h[1];


/////////////////////////////////           P4PServer            /////////////////////////////////////////////////////
        P4PServer server = new P4PServer(dimension, FieldSize_larger_than_bitLength_Sim, bitLength, zkpIterations, g, h);
        ////////////////////////////////////////////////////////////////////////



        long[] sum_in_Sim = new long[dimension];
        long[] v_Add_PeerSum = new long[dimension];

        StopWatch proverWatch = new StopWatch();
        StopWatch verifierWatch = new StopWatch();
        double delta = 1.5;
//        double [] delta_array = new double[user_num];
        int nfails = 0;
        for(int kk = 0; kk < nLoops; kk++) {
            int nQualifiedUsers = 0;
            boolean passed = true;
            server.init(); // Must clear old states and data
            server.generateChallengeVectors();
            for(int i = 0; i < dimension; i++) {
                sum_in_Sim[i] = 0;   v_Add_PeerSum[i] = 0;
            }
            for(int user_id = 0; user_id < user_num; user_id++) {
                long start = System.currentTimeMillis();
                long innerProductTime = 0;
                long randChallengeTime = 0;
                boolean shouldPass;
                // We should create a vector that passes the zkp
                if (worstcase) shouldPass = true;     // Test the worst case
                else shouldPass = rand.nextBoolean();
                System.out.println("Loop " + kk + ", user " + user_id + ". shouldPass = " + shouldPass);
                if (shouldPass){
                    delta = 0.5;
                    shouldPass_Counter[0]++;
                }else{
                    delta = 2.0;
                    shouldPass_Counter[1]++;
                }

                double l2_norm_double_5dot49_Sim = (double)L_1099511627776*delta;


                ////// 1. Generate Data_long_Array && UserVector2 & //////
                data_long_1arr = Util.randVector(dimension, FieldSize_larger_than_bitLength_Sim, l2_norm_double_5dot49_Sim);
                //I🌟 【 data_long = Util.randVector(dim, F, l2norm) 】

                UserVector2 uv2 = new UserVector2(data_long_1arr, FieldSize_larger_than_bitLength_Sim, bitLength, g, h);




// 2. Generate ServerVector & PeerVector
// peerVector from  Util.mod(data[generate_shares_ui] - serverUserVector[generate_shares_ui], F);
                uv2.generateShares();
                 //II🌟 uv2.generateShares(); 【 serverUserVector_UV2 = Util.randVector(dim, F, 0) 】
                // III🌟 uv2.main() 【 data_uv2_main = Util.randVector(m, F, l2_L_delta); 】


// 3. set CheckCoVector through server Challenge_Vector for Each User
                uv2.setChecksumCoefficientVectors(server.getChallengeVectors());
                proverWatch.start();



// 4. peerProof & serverProof
                UserVector2.L2NormBoundProof2 peerProof =
                        (UserVector2.L2NormBoundProof2)uv2.getL2NormBoundProof2(false);
                UserVector2.L2NormBoundProof2 serverProof =
                        (UserVector2.L2NormBoundProof2)uv2.getL2NormBoundProof2(true);
                proverWatch.pause();





// 5. setUserVector(uid, U) & setProof(uid, sProof)
                server.setUserVector(user_id, uv2.getU());
                server.setProof(user_id, serverProof);




// 6. []vv=UV2 &  pv.setV(vv) & setChecksumCoefficientVectors()
                long[] vv_peerVector = uv2.getV();
                UserVector2 pv = new UserVector2(dimension, FieldSize_larger_than_bitLength_Sim, bitLength, g, h);
                pv.setV(vv_peerVector);
                pv.setChecksumCoefficientVectors(server.getChallengeVectors());
                verifierWatch.start();


// peer Proof //
// 7. peerPassed verify2(peerProof); disqualifyUser(user_id);  setY(uid, Y)
                boolean peerPassed = pv.verify2(peerProof);
                verifierWatch.pause();
                System.out.println("here");
                if(!peerPassed){
                    System.out.println("!peerPassed");
                    server.disqualifyUser(user_id);
                }
                else{
                    server.setY(user_id, pv.getY_UV2());
                }

                /**
                 * Note that peer's verification simply computes some 
                 * commitments the peer's shares of the checksums (i.e. the 
                 * Y's) which should be forwarded to the server. We simulate 
                 * this by the server.setY call. The server then use them to
                 * verify the proof. This is where the real verification 
                 * happens. The peer's verification actually always returns 
                 * true.
                 */

                // 8. shouldPass
                shouldPass = l2_norm_double_5dot49_Sim < L_1099511627776;   // Correct shouldPass using actual data.
                if(shouldPass) {
                    nQualifiedUsers++;
                    Util.vectorAdd(sum_in_Sim, data_long_1arr, sum_in_Sim, FieldSize_larger_than_bitLength_Sim);
                    Util.vectorAdd(v_Add_PeerSum, vv_peerVector, v_Add_PeerSum, FieldSize_larger_than_bitLength_Sim);
                }
            }

            // 9. server.setPeerSum(v)
            // Now the server is ready to verify
            server.setPeerSum(v_Add_PeerSum);
            verifierWatch.start();
            server.compute();
            verifierWatch.pause();

            // 10. server.getVectorSum();
            // Check if the vecSum_res is right
            long[] vecSum_res = server.getVectorSum();
            System.out.println("getVectorSum from server: "+ Arrays.toString(vecSum_res));

            // 11. dimension Util.mod(sum, F);
            for(int ii = 0; ii < dimension; ii++) {
                if(vecSum_res[ii] != Util.mod(sum_in_Sim[ii], FieldSize_larger_than_bitLength_Sim)) {
                    System.out.println("\tElement " + ii
                            + " don't agree. Computed: "
                            + vecSum_res[ii] + ", should be "
                            + Util.mod(sum_in_Sim[ii], FieldSize_larger_than_bitLength_Sim));
                    passed = false;
                    nfails++;
                    break;
                }
            }
            if(passed)
                System.out.println("Test " + kk + " passed. Number of qualified users "
                        + " should be " + nQualifiedUsers + ". Server reported "
                        + server.getNQulaifiedUsers());
            else
                System.out.println("Test " + kk + " failed. Number of qualified users should be "
                        + nQualifiedUsers + ". Server reported "
                        + server.getNQulaifiedUsers());

        }

        verifierWatch.stop();
        proverWatch.stop();
        long end = System.currentTimeMillis();

        System.out.println("Total tests run: " + nLoops + ". Failed: " + nfails);
        System.out.println("\n  Prover time            Verifier time           Total");
        System.out.println("============================================================");
        System.out.println("    " + (double)proverWatch.getElapsedTime()/nLoops
                + "                 "
                + (double)verifierWatch.getElapsedTime()/nLoops
                + "              "
                + ((double)(proverWatch.getElapsedTime()
                +verifierWatch.getElapsedTime()))/nLoops);
        System.out.println("Note that the time is for all "+user_num+" users in ms.");
        System.out.println("Also note that the prover needs to compute proofs"
                + " for both the server and the privacy peer.");


    }
}


