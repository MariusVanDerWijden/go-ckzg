// Copyright Marius van der Wijden

//go:build !gofuzz && cgo
// +build !gofuzz,cgo

// package gockzg wraps the c-kzg library.
package gockzg

/*
#cgo LDFLAGS: -L ./c-kzg/lib/libblst.a
#cgo CFLAGS: -I ./c-kzg/
#cgo CFLAGS: -I ./c-kzg/min-src/
#cgo CFLAGS: -I ./blst/
#cgo CFLAGS: -I ./blst/src/

#include "./blst/bindings/blst.h"
#include "./c-kzg/min-src/c_kzg_4844.h"
#include "./c-kzg/min-src/c_kzg_4844.c"
#include <stdio.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

var settings *C.KZGSettings

type KZGCommitment C.KZGCommitment
type KZGProof C.KZGProof
type BLSFieldElement C.BLSFieldElement

const trustedSetupFile = "filename"

func init() {
	trustedSetup := []byte(trustedSetupFile)
	r := []byte("r")
	setup := C.fopen((*C.char)(unsafe.Pointer(&trustedSetup[0])), (*C.char)(unsafe.Pointer(&r[0])))
	C.load_trusted_setup(settings, setup)
}

func BLSFieldElementFromBytes(elements [32]byte) *BLSFieldElement {
	var out C.BLSFieldElement
	C.bytes_to_bls_field(&out, (*C.uchar)(unsafe.Pointer(&elements[0])))
	elem := BLSFieldElement(out)
	return &elem
}

func ComputeKZGProof(blobs [][32]byte) (*KZGProof, error) {
	var out C.KZGProof
	b := blobsFromBytes(blobs)
	ret := C.compute_aggregate_kzg_proof(&out, b, (C.ulong)(len(blobs)), settings)
	if ret != 0 {
		return nil, errors.New("error creating proof")
	}
	proof := KZGProof(out)
	return &proof, nil
}

func blobsFromBytes(blobs [][32]byte) *[4096]C.BLSFieldElement {
	out := make([][4096]C.BLSFieldElement, 0, len(blobs))
	for i := 0; i < len(blobs); i++ {
		for k := 0; k < 4096; k++ {
			C.bytes_to_bls_field(&out[i][k], (*C.uchar)(unsafe.Pointer(&blobs[i][k])))
		}
	}
	return (*[4096]C.BLSFieldElement)(unsafe.Pointer(&out[0]))
}

func VerifyKZGProof(commitments []*KZGCommitment, blobs [][32]byte, proof *KZGProof) error {
	if len(commitments) != len(blobs) {
		return errors.New("commitment length != blob length")
	}
	var out C.bool
	b := blobsFromBytes(blobs)
	ret := C.verify_aggregate_kzg_proof(&out, b, (*C.KZGCommitment)(unsafe.Pointer(&commitments[0])), (C.ulong)(len(commitments)), (*C.KZGProof)(proof), settings)
	if ret != 0 {
		return errors.New("error verifying proof")
	}
	if !out {
		return errors.New("verification failed")
	}
	return nil
}

// BlobToKZGCommitment turns a blob into a KZG commitment
func BlobToKZGCommitment(blob []byte) *KZGCommitment {
	var out C.KZGCommitment
	fr_elements := (*C.BLSFieldElement)(unsafe.Pointer(&blob[0]))
	C.blob_to_kzg_commitment(&out, fr_elements, settings)
	com := KZGCommitment(out)
	return &com
}
