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

import p4p.util.Util;
import p4p.util.StopWatch;
import p4p.util.P4PParameters;
import p4p.crypto.SquareCommitment;
import p4p.crypto.Proof;
import p4p.crypto.BitCommitment;
import p4p.crypto.Commitment;
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

    private static int k = 512;     // Security parameter
    private static int m = 10;      // User vector dimension
    private static int n = 10;      // Number of users
    private static int l = 40;      // Bit length of L

    /**
     * Start a simulation.
     */
    public static void main(String[] args) {
        int nLoops = 10;
        boolean doBench = false;
        boolean worstcase = false;
        /**
         * Test the worst case cost. i.e. every vector should pass. This is
         * when the verifier spends longest time.
         */

        // Definie the number of iterations that the bound ZKP must have:
        int zkpIterations = 50;

        for (int i = 0; i < args.length; ) {
            String arg = args[i++];
            if(arg.length() > 0 && arg.charAt(0) == '-') {
                if (arg.equals("-k")) {
                    try {
                        k = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        k = 512;
                    }
                }
                else if(arg.equals("-m")) {
                    try {
                        m = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        m = 10;
                    }
                }
                else if(arg.equals("-n")) {
                    try {
                        n = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        n = 10;
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
                        l = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        l = 40;
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

        System.out.println("k = " + k);
        System.out.println("m = " + m);
        System.out.println("n = " + n);
        System.out.println("nLoops = " + nLoops);

        // Setup the parameters:
        P4PParameters.initialize(k, false);
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

        long L = ((long)2)<<l - 1;
        long F = BigInteger.probablePrime(Math.min(l+30,62), rand).longValue();
        // Make the field size to be 10 bits larger than l

        // Or just make F 62 bits? Note that we can't use 64 bit since there is no
        // unsigned long in java.
        //F = BigInteger.probablePrime(62, rand).longValue();

        int N = zkpIterations;
        System.out.println("l = " + l + ", L = " + L);
        System.out.println("F = " + F);
        System.out.println("zkpIterations = " + zkpIterations);

        // Generate the data and the checksum coefficient vector:
        long[] data = new long[m];
        int[][] c = new int[zkpIterations][];
        NativeBigInteger[] bi = P4PParameters.getGenerators(2);
        g = bi[0];
        h = bi[1];

        P4PServer server = new P4PServer(m, F, l, zkpIterations, g, h);

        long[] s = new long[m];
        long[] v = new long[m];

        StopWatch proverWatch = new StopWatch();
        StopWatch verifierWatch = new StopWatch();
        double delta = 1.5;
        int nfails = 0;

        for(int kk = 0; kk < nLoops; kk++) {
            int nQulaifiedUsers = 0;
            boolean passed = true;
            server.init(); // Must clear old states and data
            server.generateChallengeVectors();
            for(int i = 0; i < m; i++) {
                s[i] = 0;   v[i] = 0;
            }
            for(int i = 0; i < n; i++) {
                long start = System.currentTimeMillis();
                long innerProductTime = 0;
                long randChallengeTime = 0;
                boolean shouldPass;
                // We should create a vector that passes the zkp
                if(worstcase) shouldPass = true;     // Test the worst case
                else shouldPass = rand.nextBoolean();
                //System.out.println("Loop " + kk + ", user " + i + ". shouldPass = " + shouldPass);
                if(shouldPass) delta = 0.5;
                else delta = 2.0;
                double l2 = (double)L*delta;
                data = Util.randVector(m, F, l2);

                UserVector2 uv = new UserVector2(data, F, l, g, h);
                // Simulating the user:
                uv.generateShares();
                uv.setChecksumCoefficientVectors(server.getChallengeVectors());
                proverWatch.start();
                UserVector2.L2NormBoundProof2 peerProof =
                        (UserVector2.L2NormBoundProof2)uv.getL2NormBoundProof2(false);
                UserVector2.L2NormBoundProof2 serverProof =
                        (UserVector2.L2NormBoundProof2)uv.getL2NormBoundProof2(true);
                proverWatch.pause();

                // The server:
                server.setUserVector(i, uv.getU());
                server.setProof(i, serverProof);

                // The peer:
                long[] vv = uv.getV();
                UserVector2 pv = new UserVector2(m, F, l, g, h);
                pv.setV(vv);
                pv.setChecksumCoefficientVectors(server.getChallengeVectors());
                verifierWatch.start();
                boolean peerPassed = pv.verify2(peerProof);
                verifierWatch.pause();

                if(!peerPassed)
                    server.disqualifyUser(i);
                else
                    server.setY(i, pv.getY());
                /**
                 * Note that peer's verification simply computes some
                 * commitments the peer's shares of the checksums (i.e. the
                 * Y's) which should be forwarded to the server. We simulate
                 * this by the server.setY call. The server then use them to
                 * verify the proof. This is where the real verification
                 * happens. The peer's verification actually always returns
                 * true.
                 */

                shouldPass = l2 < L;   // Correct shouldPass using actual data.
                if(shouldPass) {
                    nQulaifiedUsers++;
                    Util.vectorAdd(s, data, s, F);
                    Util.vectorAdd(v, vv, v, F);
                }
            }

            // Now the server is ready to verify
            server.setPeerSum(v);
            verifierWatch.start();
            server.compute();
            verifierWatch.pause();
            // Check if the result is right
            long[] result = server.getVectorSum();

            for(int ii = 0; ii < m; ii++) {
                if(result[ii] != Util.mod(s[ii], F)) {
                    System.out.println("\tElement " + ii
                            + " don't agree. Computed: "
                            + result[ii] + ", should be "
                            + Util.mod(s[ii], F));
                    passed = false;
                    nfails++;
                    break;
                }
            }
            if(passed)
                System.out.println("Test " + kk + " passed. Number of qualified users "
                        + " should be " + nQulaifiedUsers + ". Server reported "
                        + server.getNQulaifiedUsers());
            else
                System.out.println("Test " + kk + " failed. Number of qualified users should be "
                        + nQulaifiedUsers + ". Server reported "
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
        System.out.println("Note that the time is for all "+n+" users in ms.");
        System.out.println("Also note that the prover needs to compute proofs"
                + " for both the server and the privacy peer.");


    }
}


