package solidity

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
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
		proofEvm           [8]*big.Int
		proofCompressedEvm [4]*big.Int
		input              [2]*big.Int
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

	g1 := new(bn254.G1Affine)
	g2 := new(bn254.G2Affine)
	g1.SetBytes(proofBytes[fpSize*0 : fpSize*2])
	proofCompressedEvm[0] = compressG1ForContract(g1)
	g2.SetBytes(proofBytes[fpSize*2 : fpSize*6])
	proofCompressedEvm[2], proofCompressedEvm[1] = compressG2ForContract(g2)
	g1.SetBytes(proofBytes[fpSize*6 : fpSize*8])
	proofCompressedEvm[3] = compressG1ForContract(g1)

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

func compressG1ForContract(g1 *bn254.G1Affine) *big.Int {
	y := new(fp.Element)
	y.Exp(g1.X, big.NewInt(3))
	y.Add(y, new(fp.Element).SetUint64(3))
	y.Sqrt(y)
	res := new(big.Int)
	g1.X.BigInt(res)
	res.Lsh(res, 1)
	if !y.Equal(&g1.Y) {
		res.Or(res, big.NewInt(1))
	}
	return res
}

func compressG2ForContract(g2 *bn254.G2Affine) (*big.Int, *big.Int) {
	a0 := new(fp.Element).SetUint64(27)
	a0.Div(a0, new(fp.Element).SetUint64(82))
	a0.Add(a0, new(fp.Element).Exp(g2.X.A0, new(big.Int).SetUint64(3)))
	tmp := new(fp.Element)
	tmp.Mul(new(fp.Element).SetUint64(3), &g2.X.A0)
	tmp.Mul(tmp, &g2.X.A1)
	tmp.Mul(tmp, &g2.X.A1)
	a0.Sub(a0, tmp)
	a0sq := new(fp.Element).Square(a0)

	a1 := new(fp.Element).SetUint64(3)
	a1.Div(a1, new(fp.Element).SetUint64(82))
	a1.Add(a1, new(fp.Element).Exp(g2.X.A1, new(big.Int).SetUint64(3)))
	tmp.Mul(new(fp.Element).SetUint64(3), &g2.X.A0)
	tmp.Mul(tmp, &g2.X.A0)
	tmp.Mul(tmp, &g2.X.A1)
	a1.Sub(a1, tmp)
	a1.Neg(a1)
	a1sq := new(fp.Element).Square(a1)

	d := new(fp.Element)
	d.Add(a0sq, a1sq)
	d.Sqrt(d)

	// Trial and error find the signs.
	for bits := 0; bits < 4; bits++ {
		dc := new(fp.Element).Set(d)
		if bits&2 != 0 {
			dc.Neg(dc)
		}
		b0 := new(fp.Element)
		b0.Add(a0, dc)
		b0.Div(b0, new(fp.Element).SetUint64(2))
		b0.Sqrt(b0)
		b1 := new(fp.Element)
		b1.Mul(b0, new(fp.Element).SetUint64(2))
		b1.Inverse(b1)
		b1.Mul(b1, a1)
		if bits&1 != 0 {
			b0.Neg(b0)
			b1.Neg(b1)
		}
		if b0.Equal(&g2.Y.A0) && b1.Equal(&g2.Y.A1) {
			r0 := new(big.Int)
			g2.X.A0.BigInt(r0)
			r0.Lsh(r0, 2)
			r0.Or(r0, big.NewInt(int64(bits)))
			r1 := new(big.Int)
			g2.X.A1.BigInt(r1)

			return r0, r1
		}
	}
	panic("impossible: no solution")
}
