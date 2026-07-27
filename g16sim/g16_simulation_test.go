package g16sim

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/test"
)

// Groth16Simulation combines:
//   - a 2-pair PairingCheck using fixed (precomputed) G2 points, and
//   - an AssertMillerLoopAndFinalExpIsOne check where one Miller loop result
//     is supplied as a witness (computed outside the circuit).
type Groth16Simulation struct {
	// Set 1: e(In1G1, In1G2) * e(In2G1, In2G2) == 1, fixed G2 points
	In1G1 sw_bls12381.G1Affine
	In1G2 sw_bls12381.G2Affine
	In2G1 sw_bls12381.G1Affine
	In2G2 sw_bls12381.G2Affine
	In3G1 sw_bls12381.G1Affine
	In3G2 sw_bls12381.G2Affine
}

func (c *Groth16Simulation) Define(api frontend.API) error {
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}

	err = pairing.PairingCheck(
		[]*sw_bls12381.G1Affine{&c.In1G1, &c.In2G1, &c.In3G1},
		[]*sw_bls12381.G2Affine{&c.In1G2, &c.In2G2, &c.In3G2},
	)
	return err
}

func randomG1G2Affines() (bls12381.G1Affine, bls12381.G2Affine) {
	_, _, G1AffGen, G2AffGen := bls12381.Generators()
	mod := bls12381.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	s2, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var p bls12381.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bls12381.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}

func TestGroth16SimulationTestSolve(t *testing.T) {
	assert := test.NewAssert(t)

	p, q := randomG1G2Affines()
	var p1, p2, p3 bls12381.G1Affine
	var q1, q2, q3 bls12381.G2Affine
	p1.Double(&p)
	q1.Double(&q)
	p2.Neg(&p1)
	q2.Set(&q)
	p3.Set(&p)
	q3.Neg(&q1)

	witness := Groth16Simulation{
		In1G1: sw_bls12381.NewG1Affine(p1),
		In2G1: sw_bls12381.NewG1Affine(p2),
		In1G2: sw_bls12381.NewG2AffineFixed(q1),
		In2G2: sw_bls12381.NewG2AffineFixed(q2),
		In3G1: sw_bls12381.NewG1Affine(p3),
		In3G2: sw_bls12381.NewG2Affine(q3),
	}
	circuit := Groth16Simulation{
		In1G2: sw_bls12381.NewG2AffineFixedPlaceholder(),
		In2G2: sw_bls12381.NewG2AffineFixedPlaceholder(),
	}

	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(err)

	t.Logf("scs: nbConstraints %d, nbInstructions: %d", ccs.GetNbConstraints(), ccs.GetNbInstructions())

	circuit = Groth16Simulation{
		In1G2: sw_bls12381.NewG2AffineFixedPlaceholder(),
		In2G2: sw_bls12381.NewG2AffineFixedPlaceholder(),
	}

	ccs, err = frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)

	t.Logf("r1cs: nbConstraints %d, nbInstructions: %d", ccs.GetNbConstraints(), ccs.GetNbInstructions())

	circuit = Groth16Simulation{
		In1G2: sw_bls12381.NewG2AffineFixedPlaceholder(),
		In2G2: sw_bls12381.NewG2AffineFixedPlaceholder(),
	}

	err = test.IsSolved(&circuit, &witness, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
}
