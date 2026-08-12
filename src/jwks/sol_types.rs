//! Solidity ABI mirrors of the `JwksOracle` types. Only used when calling the
//! contract; serialization-level types live in [`super`].

use alloy_sol_types::sol;

sol! {
    #[derive(Debug)]
    struct NotarizedJwksProof {
        bytes notarySignature;
        bytes32 domainHash;
        bytes32 clientRandom;
        bytes32 serverRandom;
        bytes serverEphemeralKey;
        bytes32 transcriptRoot;
        uint256 timestamp;
        bytes32[] domainPath;
        bytes32[] endpointPath;
    }

    #[derive(Debug)]
    struct JwkClaim {
        bytes jwkBytes;
        bytes32[] jwkPath;
        bytes kid;
        bytes nB64url;
    }

    // The full contract definition with #[sol(rpc)] lives in the calling
    // binary (which depends on alloy with the `contract` feature). This
    // module is type-only.
}
