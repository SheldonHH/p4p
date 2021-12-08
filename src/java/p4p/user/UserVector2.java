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

package p4p.user;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Vector;


import net.i2p.util.NativeBigInteger;

import p4p.util.Util;
import p4p.util.StopWatch;
import p4p.util.P4PParameters;
import p4p.crypto.SquareCommitment;
import p4p.crypto.Proof;
import p4p.crypto.BitCommitment;
import p4p.crypto.ThreeWayCommitment;
import p4p.crypto.Commitment;

/**
 * Changes:
 *
 *   12/05/2005: Moved to user package.
 */


/**
 *
 * A new UserVector class that uses the sum of squares method to check the
 * vector L2 norm bound. This was adopted from the original p4p.UserVector2.java.
 * <p>
 * Note that both the prover (the user) and the verifiers (the server and the
 * privacy peer) use this class to hold data, construct and verify the proof.
 * Different parties use different methods and access different members. The
 * user will construct a full <code>UserVector2</code>. The privacy peer only
 * sets and accesses the <code>v</code> part of the data (by calling
 * {@link #setV(long[])}, {@link #getV()} and {@link #getL2NormBoundProof2(boolean)})
 * with argument <code>false</code>.
 * The server manipulates the <code>u</code> part via {@link #setV(long[])},
 * {@link #getV()} and {@link #getL2NormBoundProof2(boolean)} with argument <code>true</code>. In addition, the
 * server should receive <code>Y's</code> from the peer and call {@link #setY}
 * to set the data. Once <code>Y</code> is set, the server can use this class
 * to verify the proof.
 *
 * @author ET 12/05/2005
 */

public class UserVector2 extends UserVector {
    private NativeBigInteger g = null;
    private NativeBigInteger h = null;
    //private SquareCommitment sc = null;

    /**
     * Constructs a (share of) user vector.
     *
     * @param data  the user vector
     * @param F     the size of the field where all user computations are
     *              performed
     * @param l     the max allowed number of bits of the L2 norm of user
     *              vector
     * @param g     the first generator used in commitment
     * @param h     the sceond generator used in commitment
     *
     */
    public UserVector2(long[] data, long F, int l, NativeBigInteger g,
                       NativeBigInteger h) {
        super(data, F, l);
        this. g = g;
        this.h = h;
        //sc = new SquareCommitment(g, h);
    }


    public UserVector2(int m, long F, int l, NativeBigInteger g,
                       NativeBigInteger h) {
        super(m, F, l);
        this. g = g;
        this.h = h;
        //sc = new SquareCommitment(g, h);
    }

    /**
     */
    public void setData(long[] data) {
        this.data = data;
        if(m == -1)
            m = data.length;
    }

    private long [] u = null;       // Server's share of user vector
    private long [] v = null;       // Privacy peer's share of user vector

    /**
     * Generates the shares of the user vector.
     */
    public void generateShares() {
        if(u == null) {
            u = new long[m];
            v = new long[m];
        }

        u = Util.randVector(m, F, 0);
        for(int i = 0; i < m; i++) {
            v[i] = Util.mod(data[i] - u[i], F);
            assert (data[i] == Util.mod(u[i] + v[i], F));
        }
    }


    /**
     * Returns the server share.
     */
    public long[] getU() {
        return u;
    }

    /**
     * Returns the peer share.
     */
    public long[] getV() {
        return v;
    }


    /**
     * Sets the server share. This is useful for server-side manipulation,
     * e.g. verifying the server-side proof.
     *
     * @param	u       the vector
     *
     */
    public void setU(long[] u) {
        this.u = u;
    }


    /**
     * Sets the peer share. This is useful for peer-side manipulation,
     * e.g. verifying the peer-side proof.
     *
     * @param	v       the vector
     *
     */
    public void setV(long[] v) {
        this.v = v;
    }


    /**
     * A zero-knowledge proof that the vector L2 norm is bounded by L.
     * <p>
     * This proof uses another method. Namely instead of checking each checksum
     * individually it checks the sum of their squares. This still gives the
     * bound but uses fewer bit commitment proofs. Note that the challenge
     * vectors are chosen from {-1, 0, 1}.
     * <p>
     * The ZKP should work as follows:
     * <p>
     * <ol>
     * <li>The server generates and broadcasts challenge vectors c1, c2, ... cN
     *     with each elements drawn from {-1, 0, 1} with IID probability
     *     {.25, .5, .25}.</li>
     * <li>For k = 1, 2, ... N, user computes the following
     *     <p>
     *     <ul>
     *     <li> xk = ck dot u mod F </li>
     *     <li> yk = ck dot v mod F </li>
     *     <li> sk = xk + yk mod F </li>
     *     <li> bk = sk - (xk + yk). bk can only be 0, or +/-F</li>
     *     </ul>
     *     <p>
     * </li>
     * <li>For k = 1, 2, ... N, user commits to all the values produced:
     *     <p>
     *     <ul>
     *     <li> Xk = COMMIT(xk)</li>
     *     <li> Yk = COMMIT(yk)</li>
     *     <li> Sk = COMMIT(sk)</li>
     *     <li> Bk = COMMIT(bk)</li>
     *     <li> Zk = COMMIT(sk^2)</li>
     *     </ul>
     *     <p>
     *     The user then constucts SquareCommitmentProof that Zk = Sk^2.
     * </li>
     * <li>The user then computes Z = Z1*Z2* ... *ZN and construct a ZKP that
     *     Z < 1/2*N*L^2 which means 2*Z < N*L^2. L is l bits. N*L^2 will be
     *     logN+2l bits. This proof is essentially consists of logN+2l
     *     BigInteger A1, A2, .. such that Z = prod{Aj*2^{j-1}} and
     *     BitCommitment proofs that each Aj encodes a bit. The verifier, on
     *     the other hand, needs to verify two things about Z:
     *     <p>
     *     <ol>
     *     <li> Z = Z1*Z2* ... *ZN</li>
     *     <li> Z = prod{Aj*2^{j-1}} where Aj contans a bit</li>
     *     </ol>
     * </li>
     * </ol>
     * <p>
     * Some of the numbers are sent to the server, some to the privacy peer.
     * But both use the UserVector2.L2NormBoundProof2 as carrier. Specifically,
     * <p>
     * <ul>
     * <li> x1, x2, ... xN and y1, ... yN: stored in long[] checksums. Acess via
     *      UserVector2.L2NormBoundProof2.getChecksums(). x's are sent to the
     *      server and the y's are sent to the privacy peer.</li>
     * <li> X1, X2, ... XN and Y1, ..., YN: these are not transmitted. Since the
     *      user will have to open the commitments anyway, the commitments
     *      themselves are not sent. Instead, the user sends r1, r2, ... rN, the
     *      random numbers used in commiting to x1, ..., xN (or y1, ..., yN).
     *      The verifier just computes X1, X2, ... (or Y1, Y2, ...), by himself.
     *      The r's are stored in BigInteger[] checksumRandomness and can be
     *      accessed via getChecksumRandomness.</li>
     * <li> B1, B2, ..., BN:  stored in <code>BigInteger</code> array
     *      <code>mdCorrector</code> and accessed via {@link #getMdCorrector()}.
     *      They are sent to the server only.</li>
     * <li> SquareCommitment.SquareCommitmentProof[] scProofs contains the proofs
     *      that Zk = Sk^2, k = 1, 2, ..., N. Note that SquareCommitmentProof
     *      contains both the commitment to the number and its square so both Sk
     *      and Zk are stored. Sent to server only. The server needs to verify that
     *      Sk = Xk*Yk*Bk, in additional to the square statement.</li>
     * <li> BitCommitment.BitCommitmentProof[] bcProofs contains the bit proofs
     *      for Z. They are only sent to the server.</li>
     * </ul>
     * <p>
     * Note that in this basic set up, the privacy peer only verifies the
     * commitments to his share of the checksums. He then forwards the data to
     * the server who will do all the verification. It is possible to change
     * this so that the privacy peer shares more work.
     */

    public class L2NormBoundProof2 extends Proof {
        private long[] checksums = null;
        // Assume there is no overflow
        private BigInteger[] checksumRandomness = null;
        // The randomness used to commit to the checksums
        private BigInteger[] mdCorrector = null;
        // The modular reduction corrector (the B's in the paper). They should
        // be the commitment to 0 or +/-F.
        private ThreeWayCommitment.ThreeWayCommitmentProof[] tcProofs = null;
        // The proofs for the above correctors.

        private SquareCommitment.SquareCommitmentProof[] scProofs = null;
        // The square proofs
        private BitCommitment.BitCommitmentProof[] bcProofs = null;
        // The bit proof for the sum of the squares
        private boolean forServer = false;
        private L2NormBoundProof2 serverProof = null;
        private L2NormBoundProof2 peerProof = null;

        ThreeWayCommitment tc = new ThreeWayCommitment(g, h, F);
        // Used to prepare the ZKP. Can be computed offline.

        /**
         * Constructs a proof.
         * @param	forServer       will build a server proof if true. Otherise
         *                          build proof for the privacy peer.
         */
        public L2NormBoundProof2(boolean forServer) {
            this.forServer = forServer;
        }

        public boolean isForServer() {
            return forServer;
        }

        /**
         * Construct the ZKP that the L2 norm of user vector is small. Note
         * that this method constructs two proofs together. One for the server,
         * the other for the privacy peer.
         */
        public void construct() {
            if(c == null || u == null)
                throw new RuntimeException("Checksum vector not set or shares"
                                           + " not generated yet.");

            serverProof = new L2NormBoundProof2(true);
            peerProof = new L2NormBoundProof2(false);

            /** For the server: */
            serverProof.checksums = new long[c.length];
            serverProof.checksumRandomness = new BigInteger[c.length];
            serverProof.scProofs =
                new SquareCommitment.SquareCommitmentProof[c.length];
            serverProof.tcProofs =
                new ThreeWayCommitment.ThreeWayCommitmentProof[c.length];

            serverProof.mdCorrector = new BigInteger[c.length];
            BigInteger squareSum = BigInteger.ZERO;
            // Sum of the squares
            BigInteger squareSumCommitment = BigInteger.ONE;
            // Commitment to the sum of the squares
            BigInteger sRandomness = BigInteger.ZERO;

            /** For the peer: */
            peerProof.checksums = new long[c.length];
            peerProof.checksumRandomness = new BigInteger[c.length];

            Commitment cm = new Commitment(g, h);
            SquareCommitment sc = new SquareCommitment(g, h);
            for(int i = 0; i < c.length; i++) {
                serverProof.checksums[i] = Util.mod(Util.innerProduct(c[i], u), F);
                peerProof.checksums[i] = Util.mod(Util.innerProduct(c[i], v), F);

                /**
                 * Note that although all the normal compuations are done in
                 * a small finite field, we don't restrict the size of the
                 * checksum here (i.e. no mod operation). We allow s to grow
                 * to check the L2 norm of the user vector.
                 */
                 peerProof.checksumRandomness[i] = Util.randomBigInteger(q);
                // We don't need to really compute the commitment here
                serverProof.checksumRandomness[i] = Util.randomBigInteger(q);

                // The peer should be done. The following are for the server:
                long s = Util.mod(serverProof.checksums[i]
                                  + peerProof.checksums[i], F);
                long b = s - (serverProof.checksums[i]+peerProof.checksums[i]);
                if(!(b == 0 || b == -F || b == F))
                    throw new RuntimeException("Modular reduction corrector "
                                               + "wrong. F = " + F + ", b = "
                                               + b);
                serverProof.mdCorrector[i] = tc.commit(b);
                serverProof.tcProofs[i] =
                    (ThreeWayCommitment.ThreeWayCommitmentProof)tc.getProof();

                // check
                if(!serverProof.mdCorrector[i].equals(serverProof.tcProofs[i]
                                                      .getCommitment()[0]))
                    throw new RuntimeException("Modular corrector " + i
                                               + " was not computed correctly.");
                // NOTE: Constructing and verifying the 3-way commitment proofs
                // are independent of user data so they can be done offline.
                // The performance reported in the paper did not include this
                // cost which is a few seconds for m = 10^6.

                BigInteger rr =
                    peerProof.checksumRandomness[i]
                    .add(serverProof.checksumRandomness[i])
                    .add(tc.getRandomness()).mod(q);

                //BigInteger cs = new BigInteger(new Long(Math.abs(s)).toString());
                BigInteger cs = new BigInteger(new Long(s).toString());
                sc.commit(cs, rr);
                serverProof.scProofs[i]
                    = (SquareCommitment.SquareCommitmentProof)sc.getProof();
                DEBUG("checksum: " + cs);

                if(debug) {
                    // lets check here:
                    if(!sc.verify(serverProof.scProofs[i])) {
                        throw new RuntimeException("Square commitment proof or"
                                                   + " verification is not "
                                                   + "working properly. i = "
                                                   + 1);
                    }
                    if(!rr.equals(sc.getSa()))
                        throw new RuntimeException("Square commitment uses "
                                                   + "the wrong randomness. "
                                                   + "i = " + 1);

                    BigInteger Y =
                        cm.commit(new BigInteger(new
                                                 Long(peerProof.checksums[i])
                                                 .toString()).mod(q),
                                  peerProof.checksumRandomness[i].mod(q));

                    BigInteger X =
                        cm.commit(new BigInteger(new
                                                 Long(serverProof.checksums[i])
                                                 .toString()).mod(q),
                                  serverProof.checksumRandomness[i].mod(q));
                    if(!serverProof.scProofs[i].getCommitment()[0]
                       .equals(X.multiply(Y).multiply(serverProof
                                                      .mdCorrector[i]).mod(p)))
                        throw new RuntimeException("S != X*Y*B. i = " + 1);
                }

                //squareSum = squareSum.add(cs.multiply(cs).mod(q)).mod(q);
                squareSum = squareSum.add(cs.multiply(cs));
                squareSumCommitment =
                    squareSumCommitment.multiply(sc.getB()).mod(p);
                // Now get the randomness used to commit to the square:
                sRandomness = sRandomness.add(sc.getSb()).mod(q);
            }

            if(debug) {
                // Lets verify if we compute the commitment to the sum of
                // squares correcly:
                System.out.print("Checking commitment to sum of squares ...");
                BigInteger ssc = cm.commit(squareSum, sRandomness);
                if(!ssc.equals(squareSumCommitment)) {
                    throw new RuntimeException("Commitment to sum of squares "
                                               + " wasn't computed correctly!");
                }
                System.out.println(" done.");
            }

            /**
             * Now we should provide a proof that squareSum contains a number x
             * such that x < 1/2*N*L^2 <=> 2x < N*L^2. L is l bits. N*L^2 will
             * be logN+2l bits. This bound will not be tight.
             */
            //squareSum = squareSum.add(squareSum).mod(q);             // 2x
            squareSum = squareSum.add(squareSum);             // 2x
            sRandomness = sRandomness.add(sRandomness).mod(q);
            squareSumCommitment =
                squareSumCommitment.multiply(squareSumCommitment).mod(p);   // 2x

            /**
             * Note on computing the checksums:
             *
             * Do not take abs. Allow it to be negative, And do not do mod q.
             * As s can be negative, s mod q is a big number and can fail the
             * ZKP.
             */

            // Lets check if the commitment was computed correctly:
            if(debug) {
                System.out.print("Checking commitment to 2*(sum of squares) ...");
                if(!cm.verify(squareSumCommitment, squareSum, sRandomness))
                    throw new RuntimeException("Commitment to 2*(sum of squares"
                                               + ") wasn't computed correctly!");
                System.out.println(" done.");
            }

            // Save it in the commitment field
            serverProof.commitment = new BigInteger[1];
            serverProof.commitment[0] = squareSumCommitment;

            int numBits =
                Math.max(squareSum.bitLength(),
                         Integer.toBinaryString(c.length).length()+2*l);
            // Even for small squares we must do all the commitments
            // otherwise leak info.
            DEBUG("squareSum has " + numBits + " bits. The limit is "
                  + (Integer.toBinaryString(c.length).length()+2*l));

            serverProof.bcProofs =
                new BitCommitment.BitCommitmentProof[numBits];
            BitCommitment bc = new BitCommitment(g, h);
            for(int i = 0; i < numBits - 1; i++) {
                BigInteger cc = bc.commit(squareSum.testBit(i));
                serverProof.bcProofs[i] =
                    (BitCommitment.BitCommitmentProof)bc.getProof();

                if(debug) {
                    if(!cc.equals(serverProof.bcProofs[i].getCommitment()[0]))
                        throw new RuntimeException("Bit commitment wasn't "
                                                   + "computed correctly!");
                }

                BigInteger r = bc.getRandomness();
                BigInteger e = BigInteger.ZERO.setBit(i);    // 2^i
                // Note that we can't use ((long)1)<<i because long doesn't
                // have enough bits!
                sRandomness = sRandomness.subtract(r.multiply(e)).mod(q);
                // -= r[i]*2^i
            }

            // Now the last bit:
            // First need to compute the randomness correctly:
            // BigInteger e = new BigInteger(new Long(((long)1)<<(numBits-1)).toString());   // 2^l
            BigInteger e = BigInteger.ZERO.setBit(numBits-1);  // 2^l
            e = e.modInverse(q);
            sRandomness = sRandomness.multiply(e).mod(q);      // divide by 2^l
            bc.commit(squareSum.testBit(numBits-1), sRandomness);
            serverProof.bcProofs[numBits-1] =
                (BitCommitment.BitCommitmentProof)bc.getProof();

            // Lets check it here:
            if(debug) {
                System.out.print("Checking homomorphism ...");
                BigInteger ZZ = BigInteger.ONE;
                BigInteger z = BigInteger.ZERO;

                for(int i = 0; i < numBits; i++) {
                    //BigInteger e = new BigInteger(new Long(((long)1)<<i).toString());  // 2^i
                    e = BigInteger.ZERO.setBit(i);
                    // Note that we can't use ((long)1)<<i because long doesn't
                    // have enough bits!

                    if(squareSum.testBit(i))
                        z = z.add(e);

                    NativeBigInteger Z =
                        (NativeBigInteger)serverProof.bcProofs[i].getCommitment()[0];

                    ZZ = ZZ.multiply(Z.modPow(e, p)).mod(p);
                }

                if(!z.equals(squareSum)) {
                    System.out.println("z = " + z);
                    System.out.println("squareSum = " + squareSum);
                    throw new RuntimeException("2*(sum of squares) wasn't "
                                               + "computed correctly!");
                }
                if(!ZZ.equals(squareSumCommitment))
                    throw new RuntimeException("Homomorphism doesn't hold!");

                System.out.println("done");
            }
        }

        /**
         * Returns the server part of the proof
         */
        public L2NormBoundProof2 getServerProof() {
            return serverProof;
        }

        /**
         * Returns the peer part of the proof
         */
        public L2NormBoundProof2 getPeerProof() {
            return peerProof;
        }

        public SquareCommitment.SquareCommitmentProof[]
            getSquareCommitmentProofs() {
            return scProofs;
        }

        public BitCommitment.BitCommitmentProof[] getBitCommitmentProofs() {
            return bcProofs;
        }

        public ThreeWayCommitment.ThreeWayCommitmentProof[] getThreeWayCommitmentProofs() {
            return tcProofs;
        }

        public long[] getChecksums() {
            return checksums;
        }

        public BigInteger[] getChecksumRandomness() {
            return checksumRandomness;
        }

        public BigInteger[] getMdCorrector() {
            return mdCorrector;
        }
    }


    private L2NormBoundProof2 proof = null;

    public Proof getL2NormBoundProof2(boolean server) {
        if(proof == null) {
            proof = new L2NormBoundProof2(server);
            proof.construct();
        }
//        System.out.println("server： "+server);
        return server ? proof.getServerProof() : proof.getPeerProof();
    }


    /**
     * The verifier.
     * <p>
     * Note that to completely verify the proof, one must first obtain the
     * peer's verification and data. The server then combines that data with
     * its own to form the complete proof.
     * <p>
     * Invoking this method on a peer's share of the vector and with a peer's
     * proof will construct <code>Y</code>. The peer can then call
     * {@link #getY()} to obtain <code>Y</code> and pass it to the server.
     */
    private BigInteger[] Y = null;
    // The peer share of the checksums. Put it here for tes
    public boolean verify2(Proof proof) {
        L2NormBoundProof2 l2Proof = (L2NormBoundProof2)proof;
        if(l2Proof.isForServer())
            return serverVerify(l2Proof, Y);
        else
            return peerVerify(l2Proof);
    }

    /**
     * Call this method to set the commitments to the y's, which should be
     * verified by the peer and passed to the server.
     */
    public void setY(BigInteger[] Y) {
        this.Y = Y;
    }


    public BigInteger[] getY() {
        return Y;
    }

    protected boolean peerVerify(L2NormBoundProof2 l2Proof) {
        long[] y = l2Proof.getChecksums();
        System.out.println("peerVerify: [y.length] "+ String.valueOf(y.length));
        // This is only getting the peer's share of the checksums.
        BigInteger[] r = l2Proof.getChecksumRandomness();
        Y  = new BigInteger[y.length];   // The commitments to the checksums

        // Peer just computes the commitments to the checksums
        Commitment cm = new Commitment(g, h);
        for(int i = 0; i < y.length; i++) {
            y[i] = Util.mod(Util.innerProduct(c[i], v), F);
            Y[i] =
                cm.commit(new BigInteger(new Long(y[i]).toString()),
                          // The checksum
                          r[i]);       // The randomness
        }

        return true;
    }


    public boolean serverVerify(L2NormBoundProof2 l2Proof, BigInteger[] Y) {
        System.out.println("serverVerify: "+ Arrays.toString(Y));
        if(Y == null)
            throw new RuntimeException("Must perform peer verification first!");

        BitCommitment.BitCommitmentProof[] bcProofs =
            l2Proof.getBitCommitmentProofs();
        SquareCommitment.SquareCommitmentProof[] scProofs =
            l2Proof.getSquareCommitmentProofs();
        ThreeWayCommitment.ThreeWayCommitmentProof[] tcProofs =
            l2Proof.getThreeWayCommitmentProofs();

        long[] x = l2Proof.getChecksums();
        // This is only getting the server's share of the checksums.
        BigInteger[] r = l2Proof.getChecksumRandomness();
        BigInteger[] X = new BigInteger[x.length];
        // The commitments to the checksums
        BigInteger[] S = new BigInteger[x.length];
        // The commitments to s
        BigInteger[] B = l2Proof.getMdCorrector();
        // The Bs

        // Check the checksums and their commitments:
        Commitment cm = new Commitment(g, h);
        ThreeWayCommitment tc = new ThreeWayCommitment(g, h, F);
        for(int i = 0; i < x.length; i++) {
            // First make sure the checksums are computed correctly:
            //if(s[i] != Math.abs(Util.innerProduct(c[i], data))) {
            if(x[i] != Util.mod(Util.innerProduct(c[i], u), F)) {
                // We are doing server
                System.out.println("Checksum " + i
                                   + " not computed correctly!");
                return false;
            }

            // Now check if the modular correctors, the Bs, are computed correctly
            if(!B[i].equals(tcProofs[i].getCommitment()[0])) {
                System.out.println("B[" + i + "]"
                                   + " not computed correctly!");
                return false;
            }

            // Check the 3-way proofs
            if(!tc.verify(tcProofs[i])) {
                System.out.println("3-Way proof " + i
                                   + " not computed correctly!");
                return false;
            }

            X[i] =
                cm.commit(new BigInteger(new Long(x[i]).toString()).mod(q),
                          // The checksum
                          r[i]);            // The randomness
            S[i] = X[i].multiply(B[i]).mod(p).multiply(Y[i]).mod(p);
        }

        // Next check that the sum of squares does not have excessive bits:
        if(bcProofs.length > Integer.toBinaryString(c.length).length()+2*l) {
            System.out.println("Sum of squares has too many bits: "
                               + bcProofs.length
                               + ", the limit is "
                               + (Integer.toBinaryString(c.length).length()+2*l));
            return false;
        }

        // Check the square proofs:
        SquareCommitment sc = new SquareCommitment(g, h);
        for(int i = 0; i < scProofs.length; i++) {
            // First check that the square commitment encodes the correct
            // number i.e. the A in scProofs is the commitment to s.
            if(!scProofs[i].getCommitment()[0].equals(S[i])) {
                System.out.println("S[" + i + "] computed incroorectly.");
                return false;
            }

            if(!sc.verify(scProofs[i])) {
                System.out.println("Square verification " + i + " failed.");
                return false;
            }
        }

        // Now the bit commitment for the sum. First check if the commitment is
        // computed correctly:
        BigInteger z = BigInteger.ONE;
        for(int i = 0; i < scProofs.length; i++) {
            z = z.multiply(scProofs[i].getCommitment()[1]).mod(p);   // *= B
        }
        z = z.multiply(z).mod(p);    // commitment[0] actually stores 2X

        if(!l2Proof.getCommitment()[0].equals(z)) {
            System.out.println("Commitment to square sum wasn't computed "
                               + "correctly.");
            return false;
        }

        // Then check each bits
        BitCommitment bc = new BitCommitment(g, h);
        BigInteger zz = BigInteger.ONE;

        DEBUG("Checking  " + bcProofs.length + " bit commitments");

        BigInteger ZZ = BigInteger.ONE;
        for(int i = 0; i < bcProofs.length; i++) {
            if(!bc.verify(bcProofs[i])) {
                System.out.println("Bit commitment verification " + i
                                   + " failed.");
                return false;
            }

            //BigInteger e = new BigInteger(new Long(((long)1)<<i).toString());  // 2^i
            BigInteger e = BigInteger.ZERO.setBit(i);
            // Note that we can't use ((long)1)<<i because long doesn't have
            // enough bits!

            NativeBigInteger Z =
                (NativeBigInteger)bcProofs[i].getCommitment()[0];
            ZZ = ZZ.multiply(Z.modPow(e, p)).mod(p);
        }

        if(!ZZ.equals(z)) {
            System.out.println("Homomorphism does not hold.");
            return false;
        }

        return true;
    }


    /**
     * Test the UserVector L2 norm bound ZKP.
     */
    public static void main(String[] args) {
        int k = 512;
        int m = 10;
        int nLoops = 10;
        int l = 40;
        boolean doBench = false;
        boolean worstcase = false;
        // test the worst case cost. i.e. every vector should pass. this is
        // when the verifier spends longest time.

        // Definie the number of iterations that the bound ZKP must have:
        int zkpIterations = 50;  // This is the N in the paper

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
                        if(l > 52) {
                            System.out.println("The system does not support l > 52. This will make "
                                               + "the field order too high so that it is not a small"
                                               + " field any more.");
                            System.exit(0);
                        }
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
                    // test the worst case cost. i.e. every vector should pass.
                    // this is when the verifier spends longest time.
                }
                else if(arg.equals("-bench")) {
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
        }
        catch(java.security.NoSuchAlgorithmException e) {
            System.err.println("NoSuchAlgorithmException!");
            e.printStackTrace();
            rand = new SecureRandom();
        }

        rand.nextBoolean();

        // Lets make l = log_2 (m)
        long L = ((long)2)<<l - 1;
        long F = BigInteger.probablePrime(l+10, rand).longValue();
        // Make the field size to be 10 bits larger than l

        // Or just make F 62 bits? Note that we can't use 64 bit since there is no
        // unsigned long in java.
        F = BigInteger.probablePrime(62, rand).longValue();

        System.out.println("l = " + l + ", L = " + L);
        System.out.println("F = " + F);
        System.out.println("zkpIterations = " + zkpIterations);

        // Generate the data and the checksum coefficient vector:
        long[] data = new long[m];
        int[][] c = new int[zkpIterations][];
        NativeBigInteger[] bi = P4PParameters.getGenerators(2);


        // chanllenger vector matrix size = m
        for(int zkp_jter = 0; zkp_jter < zkpIterations; zkp_jter++){
            c[zkp_jter] = new int[m];
        }

        int nfails = 0;

        StopWatch proverWatch = new StopWatch();
        StopWatch verifierWatch = new StopWatch();
        long innerProductTime = 0;
        long randChallengeTime = 0;
        boolean shouldPass = false;

        System.out.println("Testing UserVector L2 bound ZKP for " + nLoops + " loops .");
        long start = System.currentTimeMillis();
        double delta = 1.5;

        for(int i = 0; i < nLoops; i++) {
            if(worstcase) shouldPass = true;     // Test the worst case
            else shouldPass = rand.nextBoolean();

            if(shouldPass) {
                delta = 0.5;
            }else {
                delta = 2.0;
            }
            double l2 = (double)L*delta;
            double sqrt_l2 = 0.;

            data = Util.randVector(m, F, l2);
            for(int j = 0; j < m; j++) {
                sqrt_l2 += (double)data[j]*(double)data[j];
            }
            sqrt_l2 = Math.sqrt(sqrt_l2);


            //                 for(int j = 0; j < zkpIterations; j++) {
            //                     c[j] = new int[m];
            //                     for(int kk = 0; kk < m; kk++) {
            //                         c[j][kk] = rand.nextBoolean() ? 1 : 0;
            //                         if(c[j][kk] == 1) // flip half of the 1's
            //                             c[j][kk] = rand.nextBoolean() ? 1 : -1;
            //                     }
            //                 }

            // The following is more efficient in generating the random challenges
            byte[] randBytes = new byte[(int)Math.ceil(2*zkpIterations*m/8)];
            long t0 = System.currentTimeMillis();
            rand.nextBytes(randBytes);
            for(int j = 0; j < zkpIterations; j++) {
                for(int kk = 0; kk < m; kk++) {
                    int byteIndex = (int)2*(j*m + kk)/8;
                    int offset = 2*(j*m + kk)%8;
                    c[j][kk] = (randBytes[byteIndex] & (1<<offset)) > 0 ? 1 : 0;
                    if(c[j][kk] == 1) // flip half of the 1's
                        c[j][kk] = (randBytes[byteIndex]
                                    & (1<<(offset+1))) > 0 ? 1 : -1;
                }
            }
            randChallengeTime += (System.currentTimeMillis() - t0);

            // Lets test how much time an inner product takes
            t0 = System.currentTimeMillis();
            Util.innerProduct(c[0], data);
            innerProductTime += (System.currentTimeMillis()-t0);

            UserVector2 uv = new UserVector2(data, F, l, bi[0], bi[1]);
            data = uv.getUserData();
            uv.generateShares();
            uv.setChecksumCoefficientVectors(c);
            proverWatch.start();
            L2NormBoundProof2 peerProof =
                (L2NormBoundProof2)uv.getL2NormBoundProof2(false);
            L2NormBoundProof2 serverProof =
                (L2NormBoundProof2)uv.getL2NormBoundProof2(true);
            proverWatch.pause();

            shouldPass = l2 < L;
            verifierWatch.start();
            uv.verify2(peerProof);   // Must verify peer proof first
            boolean didPass = uv.verify2(serverProof);
            verifierWatch.pause();

            if(shouldPass != didPass) {
                nfails++;
                System.out.println("Test No. " + i + " failed. shouldPass = "
                                   + shouldPass + ", result = " + didPass
                                   + ". l2 = " + l2
                                   + ". sqrt_l2 = " + sqrt_l2);
            }
            else
                System.out.println("Test No. " + i
                                   + " passed. shouldPass = didPass = "
                                   + shouldPass
                                   + ". l2 = " + l2
                                   + ". sqrt_l2 = " + sqrt_l2);
        }
        verifierWatch.stop();
        proverWatch.stop();
        long end = System.currentTimeMillis();

        System.out.println("UserVector L2 norm ZKP: " + nLoops
                           + " loops. Failed " + nfails + " times. ms per loop:");
        System.out.println("\n   Prover time          Verifier time             Total");
        System.out.println("============================================================");
        System.out.println("    " + (double)proverWatch.getElapsedTime()/(double)nLoops
                           + "                 "
                           + (double)verifierWatch.getElapsedTime()/(double)nLoops
                           + "                 "
                           + (double)(proverWatch.getElapsedTime()+verifierWatch.getElapsedTime())/(double)nLoops);
        System.out.println("============================================================");
        System.out.println("Total time: " + (end-start) + " ms. Average: "
                           + (double)(end-start)/(double)nLoops + " ms per loop"
                           + ". Failure rate: " + (double)nfails/(double)nLoops);

        System.out.println("Time for doing 1 experiement (ms): "
                           + (double)(end-start)/(double)nLoops);
        System.out.println("Time for doing 1 inner product (ms): "
                           + (double)innerProductTime/(double)nLoops);
        System.out.println("Time for generating N challenge vectors (ms): "
                           + (double)randChallengeTime/(double)nLoops);


    }
}

