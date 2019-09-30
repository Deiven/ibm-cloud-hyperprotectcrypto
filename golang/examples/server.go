/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"crypto/tls"
	"encoding/asn1"
	"fmt"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const ep11_address = "<grep11_server_address>:<port>"

var ep11_callOpts = []grpc.DialOption{
	grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
	grpc.WithPerRPCCredentials(&util.IAMPerRPCCredentials{
		APIKey:   "<ibm_cloud_apikey>",
		Endpoint: "<https://<iam_ibm_cloud_endpoint>",
		Instance: "<hpcs_instance_id>",
	}),
}

func GenerateS256Seed() {

}

func DeriveS256KeyPair() {

}

func GenerateS256KeyPair() ([]byte, []byte) {
	conn, err := grpc.Dial(ep11_address, ep11_callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	//ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	ecParameters, err := asn1.Marshal(util.OIDNamedCurveSECP256K1)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	publicKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_EC_PARAMS, ecParameters),
		util.NewAttribute(ep11.CKA_VERIFY, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	privateKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_SIGN, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyECTemplate,
		PrivKeyTemplate: privateKeyECTemplate,
	}
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated ECDSA PKCS key pair: %x, %x", generateKeyPairStatus.PrivKey, generateKeyPairStatus.PubKey)
	return generateKeyPairStatus.PrivKey, generateKeyPairStatus.PubKey
}

func SignS256(privKey []byte, hash []byte) []byte {
	conn, err := grpc.Dial(ep11_address, ep11_callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)
	// Sign data
	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: privKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}
	//signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  hash,
	}
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}
	fmt.Println("Data signed :%x", SignResponse.Signature)

	return SignResponse.Signature
}
