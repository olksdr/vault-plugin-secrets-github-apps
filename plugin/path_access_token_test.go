package gh

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestAccessToken(t *testing.T) {
	t.Parallel()

	b, reqS := getTestBackend(t)
	config := map[string]interface{}{
		"app_id": 12345,
		"private_key": `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtwe80A1q5ZUHhHXRzWrXmUow5sbyj7HGVLAdcRNzpAJl3jvo
HM6L81D7jSMNEHFcoj8EOz0++u1LfQsalxQXoNgnWedA2AvPOZKXltDwlTp1TjFI
HFXYGcNitjGkEQN6v9OOfJ5U7IkHyOKw7AU9l8W03g2R2C1QXQ8+zi685rJ12exY
81yERKJa0B5d3tS+VIg9oEELB/jw/HqTO0owPfYEZ+3Fm3rQB9n9JJSvakAds4Gy
zoRvUPQmppO9KQG+aXF3HPXGQMh8JjmZI36Pg7M/FqB+Rg2FPVVGKsNtrWJZpe8z
MQlYw8vkPKnL1SOUhD+QcCu8dlT0xDd+BC5EowIDAQABAoIBAFOLCpoEpdhpL+c8
SCl1LTfg73VHNgx03sxlHuswL8aa+Zh4y7fqZ2MGgeuoJhxtQhUkom/PwuGSUrSe
zuJK34YhY8Tbk3OJ4GqtCNhkQow7BLRONlYIsP0BfBshiXvilLLeg9lKBAV7frwp
DQyOT9DpA2ef1gRQmq//d3FxT/QUl5buxkjRqWa5KH8YjyUkzgidnRpBWLnoju36
KUpGRy8v+wM4TU1qTr4OS/bBLbKSSGAw1jJxd2TS7Lcc7sx+Gi1WQltPZdYVwN/p
Uzzl1cpbBRn6HucSnuz4r8uG9GPC4u5AbRc5Vivw9cqp2uZfC90pjFDguEW88zX3
EaIgeFECgYEA3zMQUhlMaQSLpWeZsHzngC0qtB2Zh3xnJCU+3gnNu7vLs4k28Qfr
OXhXlpuctcGRGi7EmogUYoOvbHxdTcNG1r15eGCz4tb1rPFwquWQHhm567sDgFJV
ICheJF6kMBNwIJ/r+8AsOWn7kJdxvGiWZ9iNrlqkqsNAY/nrLWtfp50CgYEA0e15
0soLBWyrn0aEc+Sw/D789JrIn9gIGNAaj5YYm0e442MyIKzlQEKMU9XtpowMmC6E
LoO/xsdlIZhN1UZvUPA0ll4JkVkNtqpD+5/gJT9QiPBN5IZjmoDq56LiQguZ0GcD
TsorhIcx7EUDtPuJaDKJoaPEgTjCx0vGtn5liT8CgYEAt25b51zrMxONQK5X3HeK
Ogjko4n/9x0CFu6VMB2WesbnrfECuivr4RtJwHi63ZTrDz2ITgev2RaoQNwkQhhO
S4UEIy42KCLJXQw/r/Nh8Zrq9RSI2BjR5M/ILtOo0+nlqKpFYmyY68Zx/G66BkFd
+pI6PiQ4WC6G6KMn5/fqcPECgYBP1HjROdf7FhollZFk6QCMy/8xnXLRpjteBDU1
iSSOWDXs8pnrZxQ+3Y+zidS30uYvMPE/JwbUtpq0rdBbXE+UfePhkp0c0rquTg1Q
MLnyMCOWD5vvXVOfO4sYzw4vg23YnHPbkHIAEdFgQdZpCoZ0Q1OnTjm50jXvx9cn
KuW9zQKBgQCThSpEyOAiFAA9Nw1yJUa8tQx3bO1lEDAu202dxN3orRkHh4obMn5Z
KIrCyzEA1sjgo8QgXUcEjgX7bq17xQZ4tAyPezVvcOXBMsvKgloOmY+EXpYThpRR
MCXLw5qoRBP2I1/T0uJsovHYej7/IJl2v/6IV634fxHR3wxm/x6H8g==
-----END RSA PRIVATE KEY-----`,
	}
	testConfigUpdate(t, b, reqS, config)

	expectedList := []string{"ownername"}
	testGetInstalls(t, b, reqS, expectedList)

	expectedToken := map[string]interface{}{
		"token":      "v1.95e975e1305082871a18677ccdfc19286b5c10a2",
		"expires_at": "2019-12-04T09:21:14Z",
		"token_type": "token",
	}
	testGetAccessToken(t, b, reqS, expectedList[0], expectedToken)
}

func testGetAccessToken(t *testing.T, b logical.Backend, s logical.Storage, org string, expected map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("token/%s", org),
		Storage:   s,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	if resp == nil || resp.Data == nil {
		t.Fatalf("expected response with secret, got response: %v", resp)
	}

	expiresAt, ok := resp.Data["expires_at"]
	if !ok {
		t.Fatalf("expected 'expires_at' field to be returned")
	}
	if expiresAt != expected["expires_at"] {
		t.Errorf("expected %s != %s", expected["expires_at"], expiresAt)
	}
	token, ok := resp.Data["token"]
	if !ok {
		t.Fatalf("expected 'token' field to be returned")
	}
	if token != expected["token"] {
		t.Errorf("expected %s != %s", expected["token"], token)
	}
	tokenType, ok := resp.Data["token_type"]
	if !ok {
		t.Fatalf("expected 'token_type' field to be returned")
	}
	if tokenType != expected["token_type"] {
		t.Errorf("expected %s != %s", expected["token_type"], expiresAt)
	}
}

func testGetInstalls(t *testing.T, b logical.Backend, s logical.Storage, expected []string) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token",
		Storage:   s,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	if resp == nil || resp.Data == nil {
		t.Fatalf("expected response with secret, got response: %v", resp)
	}

	orgs, ok := resp.Data["organizations"]
	if !ok {
		t.Fatalf("expected 'organizations' field to be returned")
	}
	if len(orgs.([]string)) != len(expected) {
		t.Errorf("expected number of records %d, but got %d", len(expected), len(orgs.([]string)))
	}

	if !reflect.DeepEqual(orgs.([]string), expected) {
		t.Errorf("expected %s != %s", expected, orgs.([]string))
	}
}
