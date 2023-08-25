package solidity

import (
	"bytes"
	"github.com/consensys/gnark/examples/exponentiate"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/suite"
)

type ExportSolidityTestSuiteGroth16 struct {
	suite.Suite

	// backend
	backend *backends.SimulatedBackend

	// verifier contract
	verifierContract *Verifier

	// groth16 gnark objects
	vk      groth16.VerifyingKey
	pk      groth16.ProvingKey
	circuit exponentiate.Circuit
	r1cs    constraint.ConstraintSystem
}

func TestRunExportSolidityTestSuiteGroth16(t *testing.T) {
	suite.Run(t, new(ExportSolidityTestSuiteGroth16))
}

func (t *ExportSolidityTestSuiteGroth16) SetupTest() {

	const gasLimit uint64 = 4712388

	// setup simulated backend
	key, _ := crypto.GenerateKey()
	auth, err := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))
	t.NoError(err, "init keyed transactor")

	genesis := map[common.Address]core.GenesisAccount{
		auth.From: {Balance: big.NewInt(1000000000000000000)}, // 1 Eth
	}
	t.backend = backends.NewSimulatedBackend(genesis, gasLimit)

	// deploy verifier contract
	_, _, v, err := DeployVerifier(auth, t.backend)
	t.NoError(err, "deploy verifier contract failed")
	t.verifierContract = v
	t.backend.Commit()

	t.r1cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &t.circuit)
	t.NoError(err, "compiling R1CS failed")

	// read proving and verifying keys
	t.pk = groth16.NewProvingKey(ecc.BN254)
	{
		f, _ := os.Open("cubic.g16.pk")
		_, err = t.pk.ReadFrom(f)
		f.Close()
		t.NoError(err, "reading proving key failed")
	}
	t.vk = groth16.NewVerifyingKey(ecc.BN254)
	{
		f, _ := os.Open("cubic.g16.vk")
		_, err = t.vk.ReadFrom(f)
		f.Close()
		t.NoError(err, "reading verifying key failed")
	}

}

func (t *ExportSolidityTestSuiteGroth16) TestVerifyProof() {

	// create a valid proof
	var assignment exponentiate.Circuit
	assignment.X = 3
	assignment.Y = 81
	assignment.E = 4

	// witness creation
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	t.NoError(err, "witness creation failed")

	// prove
	proof, err := groth16.Prove(t.r1cs, t.pk, witness)
	t.NoError(err, "proving failed")

	// ensure gnark (Go) code verifies it
	publicWitness, _ := witness.Public()
	err = groth16.Verify(proof, t.vk, publicWitness)
	t.NoError(err, "verifying failed")

	// get proof bytes
	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	// solidity contract inputs
	var (
		proofEvm [8]*big.Int
		input    [2]*big.Int
	)

	// proof.Ar, proof.Bs, proof.Krs
	proofEvm[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	proofEvm[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	proofEvm[2] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	proofEvm[3] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	proofEvm[4] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	proofEvm[5] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	proofEvm[6] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	proofEvm[7] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	proofCompressedEvm, err := t.verifierContract.CompressProof(&bind.CallOpts{}, proofEvm)

	// public witness
	input[0] = new(big.Int).SetUint64(3)
	input[1] = new(big.Int).SetUint64(81)

	// call the contract
	err = t.verifierContract.VerifyProof(&bind.CallOpts{}, proofEvm, input)
	t.NoError(err, "calling verifier on chain gave error")

	err = t.verifierContract.VerifyCompressedProof(&bind.CallOpts{}, proofCompressedEvm, input)
	t.NoError(err, "calling verifier on chain gave error")

	// (wrong) public witness
	input[0] = new(big.Int).SetUint64(42)

	// call the contract should fail
	err = t.verifierContract.VerifyProof(&bind.CallOpts{}, proofEvm, input)
	t.Error(err, "calling verifier on chain succeeded, and shouldn't have")

	err = t.verifierContract.VerifyCompressedProof(&bind.CallOpts{}, proofCompressedEvm, input)
	t.Error(err, "calling verifier on chain succeeded, and shouldn't have")

}
