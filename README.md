# PostQuantumCryptography
### Exploring Quantum Code-Breaking and its Advantages
__Abstract:__ This project delves into the potential of quantum computing for code-breaking,
specifically focusing on its advantages over classical computing methods. We will explore
the limitations of classical algorithms like brute force, which exhibit exponential time
complexity when dealing with complex encryption schemes.

__Focus:__ Our primary focus will be on __post quantum cryptography__ and how classical encryption (Like RSA and ECC) is at a risk due to Quantum computers. We will be exploring what post quantum cryptography does to address this?

### Methodology:
1. __Literature review:__ We will conduct a comprehensive literature review of relevant
research papers and articles to gain a deeper understanding of:
* Classical code-breaking techniques, including brute force and cryptanalysis.
* Quantum code-breaking techniques, with a specific emphasis on Shor's
algorithm and its theoretical foundation in quantum mechanics concepts like
superposition and entanglement.
* Understand exsisting algoritms that are not broken by quantum cryptography and explore the fundamental properties behind such processes
2. __Implementation:__ We will try to implement algorithms to understand the field of post quantum cryptography which includes:
  * Super Singular Isogeny key exchange(SIKE) one of the initial  methods used in post quantum cryptography
  * GGH algorithm, explore its primary failures  and understand/implement the current improvements that the lattice based methods employ in the NIST organised competition.
  * Learning with errors.

After this we seek to explore other methods of post-quantum cryptography and report on them depending on availability of time. The idea is to compare and contrast other ways of creating np hard problems for quantum computers and also understanding non-lattice techniques like singular-isogeny, code-based, hash based or multivariate. Following the report we seek to either propose a possible improvement on one of the lattice or non lattice based technique’s algorithms or alternatively pick a novel domain of mathematically complex problems and use them to make a simple encryption algorithm that confirms to standards of post-quantum cryptography, a possible domain that was __chaos modelling__ and __chaos based cryptography__.

__Expected Outcomes:__
* Gain a deeper understanding of the theoretical underpinnings of classical and
quantum code-breaking algorithms.
* Demonstrate the computational advantage of Shor's algorithm over classical
methods through a simulated implementation and complexity analysis.
* Raise awareness of the urgency for developing and implementing post-quantum
cryptography (PQC) to mitigate the threat of quantum attacks on existing encryption
schemes.
