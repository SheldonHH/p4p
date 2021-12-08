P4P (Peers for Privacy) 
=======================

P4P is a practical framework for privacy-preserving distributed computation.
See http://www.cs.berkeley.edu/~duan/research/p4p.html for detailed 
information.


o Interesting classes/packages:

  - p4p.crypto: includes a number of commitment schemes and their 
    zero-knowledge proofs.
  - p4p.user.UserVector2: implements the ZKP that the user vector's L2-norm 
    is bounded by a constant L. Used to restrict the influence a malicious 
    user could have on the computation.
  - p4p.sim: includes simulation samples for the P4P computation. 


o Build and Running the Benchmark/Samples

At the directory where the code is extracted, use the command

    ant

to build.

To generate the Javadoc, type

   ant javadoc

The script p4p contained in the bin/ directory can be used to start a p4p 
program. Each class in the package typically includes test code which can be 
run with

   ./bin/p4p classname

For example, to run the p4p.user.UserVector2 testing code, which tests the 
L2-norm ZKP, type

   ./bin/p4p p4p.user.UserVector2

Each class can be invoked with various options. Please see the source code 
of the corresponding class for details. For example, the following command

   ./bin/p4p p4p.user.UserVector2 -k 1024 -l 20

starts testing the L2-norm ZKP with security parameter 1024 and a 20-bit L.
The system has some pre-generated parameters for the case of k = 1024 so 
using this option can skip the parameter generation process which can be 
slow.

Please send questions, comments or bug reports to duan@cs.berkeley.edu.

