package gockzg

import "testing"

func TestWalkthrough(t *testing.T) {
	blobs := make([][32]byte, 0)
	proof, err := ComputeKZGProof(blobs)
	if err != nil {
		panic(err)
	}
	com := BlobToKZGCommitment(blobs[0][:])
	if err := VerifyKZGProof([]*KZGCommitment{com}, blobs, proof); err != nil {
		panic(err)
	}
}
