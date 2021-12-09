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

package p4p.server;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Vector;
import java.util.Hashtable;
import java.util.Map;

import net.i2p.util.NativeBigInteger;

import p4p.util.Util;
import p4p.util.StopWatch;
import p4p.util.P4PParameters;
import p4p.user.UserVector2;

/**
 * 
 * The P4P server class.
 *
 * @author ET 12/02/2005
 */


/**
 * FIXME:
 *
 * Currently this is just a data structure for holding the server data and 
 * methods. The real server should be client-driven and multithreaded. i.e. 
 * when there is a client sending data, the server should spawn a thread to 
 * handle it. The threat could update the internal state of this class based
 * on actual user data. We are now only using the class in a simulation 
 * framework to verify the correctness and the efficiency of the protocols.
 */

public class P4PServer extends P4PParameters {
    private NativeBigInteger g = null;
    private NativeBigInteger h = null;
    
    protected int dimension_Ser = -1;            // The dimension of user vector
    protected long group_order_F_Server = -1;
    /**
     * The order of the (small) finite field over which all the computations 
     * are carried out. It should be a prime of appropriate bit-length (e.g. 
     * 64 bits).
     */
    
    protected long L = -1;
    protected int max_bits_2_norm_user_vector_l;   // The max number of bits of the 2 norm of user vector
    protected int Num_Checksum_to_Compute_Server = 50;     // The number of chechsums to compute. Default 50
    private int challenge_vectors_Ser[][] = null; // The challenge vectors  
    private long[] acc_vector_sum_Server = null;         // The accumulated vector sum
    private long[] peerSum = null;   // The peer's share of the vector sum
    
    /**
     * A class holding user information, including his data vector (share), 
     * its validity ZKP etc.
     */
    public class UserInfo {
        private int ID;
        private long[] v = null;
        private UserVector2.L2NormBoundProof2 proof = null;  
        // The L2 norm bound proof. Should be passed to us by the user.
        private BigInteger[] Y_commitments_to_peer_share_of_checksum_Ser = null;
        // The commitments to the peer's share of the checksums.

        public UserInfo(int user, long[] v) {
            ID = user;
            this.v = v;
        }
        
        /**
         * @return Returns the vector v.
         */
        public long[] getVector() {
            return v;
        }
        
        /**
         * Update the user vector.
         * @param v The new vector to set.
         */
        public void setVector(long[] v) {
            this.v = v;
        }
        
        /**
         * @return Returns the user ID.
         */
        public int getID() {
            return ID;
        }
        
        /**
         * @return Returns the proof.
         */
        public UserVector2.L2NormBoundProof2 getProof() {
            return proof;
        }
        /**
         * Set the l2 norm proof.
         * @param proof The proof to set.
         */
        public void setProof(UserVector2.L2NormBoundProof2 proof) {
            this.proof = proof;
        }
        
        /**
         */
        public void setY(BigInteger[] Y_commitments_to_peer_share_of_checksum) {
            this.Y_commitments_to_peer_share_of_checksum_Ser = Y_commitments_to_peer_share_of_checksum;
        }
        
        /**
         */
        public BigInteger[] getY() {
            return Y_commitments_to_peer_share_of_checksum_Ser;
        }
    }
    
    private Hashtable<Integer, UserInfo> usersMap = 
        new Hashtable<Integer, UserInfo>();

    /**
     */
    public P4PServer(int m, long F, int l, int N_zkpIterations, NativeBigInteger g,
                     NativeBigInteger h) {
        if(F < 0)
            throw new RuntimeException("Field order must be positive.");
        
        this.dimension_Ser = m;
        this.group_order_F_Server = F;
        this.max_bits_2_norm_user_vector_l = l;
        this.L = ((long)1)<<l - 1;
        this.Num_Checksum_to_Compute_Server = N_zkpIterations;
        this.g = g;
        this.h = h;
        
        init();
    }

    /**
     */
    public void init() {
        if(acc_vector_sum_Server == null)
            acc_vector_sum_Server = new long[dimension_Ser];
        
        for(int i = 0; i < dimension_Ser; i++)
            acc_vector_sum_Server[i] = 0;
        usersMap.clear();
    }
    
    /**
     * Sets a (share of) user vector.
     *
     * @param user   user ID
     * @param v      an m-dimensional vector
     *
     */
    public void setUserVector(int user, long[] v) {
        if(v.length != dimension_Ser)
            throw new IllegalArgumentException("User vector dimension must agree.");

        UserInfo userInfo = usersMap.get(user);
        if(userInfo == null)
            userInfo = new UserInfo(user, v);
        else
            userInfo.setVector(v);
        
        usersMap.put(user, userInfo);
    }

    /**
     * Disqualify a user and remove his (share of) vector.
     *
     * @param user  user ID
     * 
     * @return <code>true</code> if the user is sucessfuly removed. 
     *         <code>false</code> if the user is not found in the record.
     */
    public boolean disqualifyUser(int user) {
        return usersMap.remove(user) == null;

    }

    public int getNQulaifiedUsers() {
        return usersMap.size();
    }

    /**
     * Set the l2 norm proof for the given user.
     * @param user The user index.
     * @param proof The proof to set.
     * @return <code>true</code> if the user is sucessfuly updated. 
     *         <code>false</code> if the user is not found in the record.
     */
    public boolean setProof(int user, UserVector2.L2NormBoundProof2 proof) {
        UserInfo userInfo = usersMap.get(user);
        if(userInfo == null)
            return false;
        userInfo.setProof(proof);
        return true;
    }

    /**
     * Sets Y for the given user.
     * @param user     The user index.
     * @param Y_commitments_to_peer_share_of_checksum       The commitments to the peer's share of the checksums
     * @return <code>true</code> if the user is sucessfuly updated. 
     *         <code>false</code> if the user is not found in the record.
     */
    public boolean setY(int user, BigInteger[] Y_commitments_to_peer_share_of_checksum) {
        UserInfo userInfo = usersMap.get(user);
        if(userInfo == null)
            return false;
        
        userInfo.setY(Y_commitments_to_peer_share_of_checksum);
        return true;
    }
    
    /**
     * Generates challenge vectors.
     */
    public void generateChallengeVectors() {
        //  byte[] randBytes = new byte[(int)Math.ceil(2*N*m/8)];
        byte[] randBytes = new byte[2*((int)Math.ceil(Num_Checksum_to_Compute_Server*dimension_Ser/8)+1)];
        int randByteslength = randBytes.length;  //== 4

        int byteIndex_idj_SRShift3 = 0;
        int[] byteIndex_idj_SRShift3_array = new int[dimension_Ser];


        // We need twice the random bits in challenge_vectors_Ser. We need half of them to flip the 1's
        Util.rand.nextBytes(randBytes);
        int mid = randByteslength/2;


        //// //// //// //// //// //// ///// challenger //// //// //// //// //// //// //// //// //// ////
        challenge_vectors_Ser = new int[Num_Checksum_to_Compute_Server][];
        //// //// //// //// ////\\\




        // challenge vector in P4PServer.java
        //  idj=i*dimension_Ser + j
        int idj = 0;
        int [] idj_array = new int[dimension_Ser];

        //  (i*dimension_Ser + j)%8
        int offset_idj_mod8 = 0;
        int [] offset_idj_mod8_arr = new int[dimension_Ser];

        // 1<<offset_idj_mod8
        int s_1Lshift_Offset = 0;
        int [] s_1left_shift_Offset_arr = new int[dimension_Ser];

        // (randBytes[byteIndex_idj_SRShift3] & (1<<offset_idj_mod8))
        int initial_challenge_AND_operator = 0;
        int [] initial_challenge_vector = new int[dimension_Ser];

        // prev_Greater_zero =  (this_randByte & (1<<offset_idj_mod8)) > 0
        boolean prev_Greater_zero;
        boolean []prev_Greater_zero_arr = new boolean[dimension_Ser];


        int first_c_vector;
        int []first_c_vector_arr = new int[dimension_Ser];

        boolean reinforce_c_vector_First_c_vector_Equal_1;
        boolean [] reinforce_c_vector_First_c_vector_Equal_1_arr =  new boolean[dimension_Ser];

        byte[] duplicate_randBytes = new byte[dimension_Ser];
        for(int i = 0; i < Num_Checksum_to_Compute_Server; i++) {
            challenge_vectors_Ser[i] = new int[dimension_Ser];
            for(int j = 0; j < dimension_Ser; j++) {
                //int byteIndex = (int)2*(i*m + j)/8;
                //int offset = 2*(i*m + j)%8;
                idj = i*dimension_Ser + j;
                idj_array[j] = idj;

                byteIndex_idj_SRShift3 = (i*dimension_Ser + j)>>3;
                byteIndex_idj_SRShift3_array[j] = byteIndex_idj_SRShift3;



                ///// offset //////
                offset_idj_mod8 = (i*dimension_Ser + j)%8;
                offset_idj_mod8_arr[j] = offset_idj_mod8;

                s_1Lshift_Offset = 1<<offset_idj_mod8;
                s_1left_shift_Offset_arr[j]=s_1Lshift_Offset;
                ///// offset //////


                initial_challenge_AND_operator = (randBytes[byteIndex_idj_SRShift3] & (1<<offset_idj_mod8));
                initial_challenge_vector[j] = initial_challenge_AND_operator;

                byte this_randByte = randBytes[byteIndex_idj_SRShift3];
                duplicate_randBytes[byteIndex_idj_SRShift3] = this_randByte;

                prev_Greater_zero = (this_randByte & (1<<offset_idj_mod8)) > 0;
                prev_Greater_zero_arr[j] = prev_Greater_zero;
                
                
                challenge_vectors_Ser[i][j] = (randBytes[byteIndex_idj_SRShift3] & (1<<offset_idj_mod8)) > 0 ? 1 : 0;
                first_c_vector = challenge_vectors_Ser[i][j];
                first_c_vector_arr[j] = first_c_vector;

                
                if(challenge_vectors_Ser[i][j] == 1){
                    // flip half of the 1's
                    challenge_vectors_Ser[i][j] = (randBytes[mid+byteIndex_idj_SRShift3] & (1<<(offset_idj_mod8+1))) > 0 ? 1 : -1;
                    reinforce_c_vector_First_c_vector_Equal_1 = true;
                    reinforce_c_vector_First_c_vector_Equal_1_arr[j] = reinforce_c_vector_First_c_vector_Equal_1;
                }
                System.out.println("End loop of Num_Checksum_to_Compute_Server: " + j);

            }
        }
        System.out.println("c Challenge Vecter: "+ Arrays.deepToString(challenge_vectors_Ser));
    }
    
    /**
     */
    public int[][] getChallengeVectors() {
        return challenge_vectors_Ser;
    }

    /**
     * Sets the peer's share of the vector sum
     * @param vv    the sum of the peer's share of the user vector
     */
    public void setPeerSum(long[] vv) {
        peerSum = vv;
        System.out.println("peerSum: " + Arrays.toString(peerSum));
    }


    /**
     * The server have received data and their proofs from enough users.
     * This fucntion is then called to compute the sum of the valid vectors.
     */

    // 使用Challeng Vector
    public void compute() {
        Object[] users = usersMap.entrySet().toArray();
        
        UserVector2 uv = new UserVector2(dimension_Ser, group_order_F_Server, max_bits_2_norm_user_vector_l, g, h);
        System.out.println("Server:: computing. There are potentially " + usersMap.size() 
                           + " users.");
        int disqualified = 0;
        System.out.println("users.length: "+users.length);
        for(int i = 0; i < users.length; i++) {
            Map.Entry<Integer, UserInfo> userEntry = 
                (Map.Entry<Integer, UserInfo>)users[i];

            UserInfo user = userEntry.getValue();
            long[] u = user.getVector();
            long[] u_server_for_U2 = u;
            
            // Verify its proof in UserVector2:
            uv.setU(u_server_for_U2);
            uv.setChecksumCoefficientVectors(challenge_vectors_Ser);

            BigInteger[] Y_U2 = user.getY();
            uv.setY(Y_U2);
            UserVector2.L2NormBoundProof2 proof = user.getProof();

            if(uv.verify2(proof)){
                System.out.println("User " + user.ID
                        + "'s vector succeed the verification.");
            }
            if(!uv.verify2(proof)) {
                System.out.println("User " + user.ID 
                                   + "'s vector failed the verification.");
                disqualifyUser(user.ID);
                // TODO: Must let the peer know about disqualified users so he can computes his share
                // of the sum (the peerSum).
                disqualified++;
                continue;
            }
            Util.vectorAdd(acc_vector_sum_Server, u, acc_vector_sum_Server, group_order_F_Server);
        }
        Util.vectorAdd(acc_vector_sum_Server, peerSum, acc_vector_sum_Server, group_order_F_Server);
        System.out.println("Server:: done computing. " + disqualified + " users disqualified.");
    }
    
    /**
     */
    public long[] getVectorSum() {
        return acc_vector_sum_Server;
    }
}

